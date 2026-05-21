// Package resourceserver implements the MCP Resource Server (RFC 9728 + MCP Auth spec).
// It runs on :8081, validates JWT access tokens issued by the Authorization Server (:8080),
// and exposes MCP tools over JSON-RPC 2.0.
package resourceserver

import (
	"encoding/json"
	"net/http"
)

// protectedResourceMetadata is the response body for RFC 9728 §3.
// This is how MCP clients discover which auth server protects this resource.
type protectedResourceMetadata struct {
	// resource is the canonical URL of this resource server (must match the
	// "aud" claim in access tokens — RFC 8707 resource indicators).
	Resource string `json:"resource"`

	// authorization_servers lists every AS that can issue tokens for this resource.
	// MCP clients pick one and run the OAuth PKCE flow against it.
	AuthorizationServers []string `json:"authorization_servers"`

	// bearer_methods_supported: "header" means Authorization: Bearer <token>
	BearerMethodsSupported []string `json:"bearer_methods_supported"`

	// scopes_supported tells clients what scopes to request.
	ScopesSupported []string `json:"scopes_supported"`
}

// NewMetadataHandler handles GET /.well-known/oauth-protected-resource (RFC 9728).
func NewMetadataHandler(resourceURL, authServerURL string) http.HandlerFunc {
	meta := protectedResourceMetadata{
		Resource:               resourceURL,
		AuthorizationServers:   []string{authServerURL},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"read", "write"},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}
}
