package resourceserver

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingToken = errors.New("missing bearer token")
	ErrInvalidToken = errors.New("invalid token")
)

// ExtractBearer pulls the token string from "Authorization: Bearer <token>".
// This is identical to the authserver version — both ends of the OAuth flow need it.
func ExtractBearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" || !strings.HasPrefix(h, "Bearer ") {
		return "", ErrMissingToken
	}
	return strings.TrimPrefix(h, "Bearer "), nil
}

// ParseJWT validates the token against the given RSA public key and returns the claims.
// Unlike the authserver version, this takes *rsa.PublicKey directly — the resource server
// never has (and never needs) the private key.
func ParseJWT(tokenStr string, pub *rsa.PublicKey) (map[string]any, error) {
	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidToken
		}
		return pub, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	// jwt.MapClaims is defined as map[string]any, so this cast is safe.
	return map[string]any(claims), nil
}

// HasScope reports whether the "scope" claim contains the required scope value.
// Per RFC 6749 §3.3, scopes in a token are space-separated strings.
func HasScope(claims map[string]any, required string) bool {
	raw, ok := claims["scope"].(string)
	if !ok {
		return false
	}
	for _, s := range strings.Split(raw, " ") {
		if s == required {
			return true
		}
	}
	return false
}
