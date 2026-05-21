package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

// registerRequest is the body of RFC 7591 §2 client registration request.
// MCP clients send this to get a client_id before starting the PKCE flow.
type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// registerResponse is the RFC 7591 §3.2 successful registration response.
type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// NewRegisterHandler handles POST /register (RFC 7591 Dynamic Client Registration).
//
// This is how MCP clients get a client_id without manual configuration.
// The full MCP Auth discovery flow is:
//  1. Client hits resource server → 401 + resource_metadata URL
//  2. Client fetches /.well-known/oauth-protected-resource → finds auth server
//  3. Client fetches /.well-known/oauth-authorization-server → finds registration_endpoint
//  4. Client calls POST /register → receives client_id   ← this handler
//  5. Client runs PKCE flow using the new client_id
func NewRegisterHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// RFC 7591 §2: request body MUST be application/json
		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRegisterError(w, "invalid_client_metadata", "request body must be valid JSON", http.StatusBadRequest)
			return
		}

		// redirect_uris is required — we need at least one to validate later in /authorize.
		if len(req.RedirectURIs) == 0 {
			writeRegisterError(w, "invalid_redirect_uri", "at least one redirect_uri is required", http.StatusBadRequest)
			return
		}

		// We only support public clients (no secret).
		// If the client explicitly requests a confidential auth method, reject it.
		if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
			writeRegisterError(w, "invalid_client_metadata", "only token_endpoint_auth_method=none is supported", http.StatusBadRequest)
			return
		}

		// Generate a random client_id. In production this would be a UUID or similar.
		// We use 16 random bytes → 22-character base64url string.
		clientID, err := generateClientID()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// Default values per RFC 7591 §2
		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}
		responseTypes := req.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}

		now := time.Now()
		store.RegisterClient(ClientInfo{
			ClientID:     clientID,
			RedirectURIs: req.RedirectURIs,
			Name:         req.ClientName,
			CreatedAt:    now,
		})

		// HTTP 201 Created — RFC 7591 §3.2
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registerResponse{
			ClientID:                clientID,
			ClientIDIssuedAt:        now.Unix(),
			RedirectURIs:            req.RedirectURIs,
			ClientName:              req.ClientName,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
		})
	}
}

func generateClientID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeRegisterError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
