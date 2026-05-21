package authserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenResponse matches the shape defined in RFC 6749 §5.1 (reused by OAuth 2.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// tokenErrorResponse is the error shape from RFC 6749 §5.2.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewTokenHandler(store *Store, kp *KeyPair, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeTokenError(w, "invalid_request", "only POST is allowed", http.StatusMethodNotAllowed)
			return
		}
		// OAuth 2.1 §3.2: token endpoint MUST use application/x-www-form-urlencoded
		if err := r.ParseForm(); err != nil {
			writeTokenError(w, "invalid_request", "could not parse form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		switch grantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(w, r, store, kp, issuer)
		case "refresh_token":
			handleRefreshTokenGrant(w, r, store, kp, issuer)
		default:
			// RFC 6749 §5.2: unsupported_grant_type
			writeTokenError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token", http.StatusBadRequest)
		}
	}
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, store *Store, kp *KeyPair, issuer string) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
		writeTokenError(w, "invalid_request", "missing required parameters", http.StatusBadRequest)
		return
	}

	authCode, ok := store.GetCode(code)
	if !ok {
		// RFC 6749 §5.2: invalid_grant
		writeTokenError(w, "invalid_grant", "unknown or expired code", http.StatusBadRequest)
		return
	}

	// Auth codes are single-use — delete immediately to prevent replay attacks.
	// This must happen before any validation so a race can't be exploited.
	store.DeleteCode(code)

	if time.Now().After(authCode.ExpiresAt) {
		writeTokenError(w, "invalid_grant", "code has expired", http.StatusBadRequest)
		return
	}

	// OAuth 2.1 §4.1.3: client_id MUST be validated
	if authCode.ClientID != clientID {
		writeTokenError(w, "invalid_client", "client_id mismatch", http.StatusUnauthorized)
		return
	}

	// OAuth 2.1 §4.1.3: redirect_uri MUST be exact-match if present in authorization request
	if authCode.RedirectURI != redirectURI {
		writeTokenError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	// RFC 7636 §4.6: PKCE S256 verification
	// S256: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
	if !verifyPKCE(codeVerifier, authCode.CodeChallenge) {
		writeTokenError(w, "invalid_grant", "code_verifier does not match code_challenge", http.StatusBadRequest)
		return
	}

	issueTokens(w, store, kp, issuer, clientID, authCode.Subject, authCode.Scope)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, store *Store, kp *KeyPair, issuer string) {
	rawRefresh := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if rawRefresh == "" || clientID == "" {
		writeTokenError(w, "invalid_request", "missing refresh_token or client_id", http.StatusBadRequest)
		return
	}

	rt, ok := store.GetRefreshToken(rawRefresh)
	if !ok {
		// RFC 6749 §5.2 + OAuth 2.1 refresh token rotation:
		// If a refresh token is presented that no longer exists, it was either
		// already rotated (normal) or replayed after theft. Either way: invalid_grant.
		writeTokenError(w, "invalid_grant", "unknown or already-used refresh token", http.StatusBadRequest)
		return
	}

	if rt.ClientID != clientID {
		writeTokenError(w, "invalid_client", "client_id mismatch", http.StatusUnauthorized)
		return
	}

	if time.Now().After(rt.ExpiresAt) {
		store.DeleteRefreshToken(rawRefresh)
		writeTokenError(w, "invalid_grant", "refresh token has expired", http.StatusBadRequest)
		return
	}

	// Rotation: delete old refresh token before issuing new one.
	// If an attacker replays the old token after this, they'll get invalid_grant.
	store.DeleteRefreshToken(rawRefresh)

	issueTokens(w, store, kp, issuer, rt.ClientID, rt.Subject, rt.Scope)
}

// issueTokens generates a JWT access token + opaque refresh token, and writes the response.
func issueTokens(w http.ResponseWriter, store *Store, kp *KeyPair, issuer, clientID, subject, scope string) {
	now := time.Now()

	// JWT access token — self-contained, no store lookup needed by resource server.
	// Claims follow RFC 7519 + RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens).
	claims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       subject,  // authenticated user
		"client_id": clientID, // the app acting on their behalf
		"scope":     scope,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid in header lets resource server pick the right key from JWKS when rotating keys.
	token.Header["kid"] = kp.KID

	accessToken, err := token.SignedString(kp.Private)
	if err != nil {
		writeTokenError(w, "server_error", "failed to sign token", http.StatusInternalServerError)
		return
	}

	// Refresh token stays opaque — it's only used by the auth server itself.
	refreshToken, err := generateToken()
	if err != nil {
		writeTokenError(w, "server_error", "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	store.SaveRefreshToken(RefreshTokenInfo{
		Token:     refreshToken,
		ClientID:  clientID,
		Subject:   subject,
		Scope:     scope,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	})

	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 §5.1: prevent token leakage via HTTP caches
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	})
}

// verifyPKCE implements RFC 7636 §4.6 S256 method:
// BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge
func verifyPKCE(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == codeChallenge
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeTokenError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(tokenErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
	})
}