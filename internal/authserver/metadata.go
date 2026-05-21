package authserver

import (
	"encoding/json"
	"net/http"
)

type ServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RevocationEndpoint            string   `json:"revocation_endpoint"`
	JWKSUri                       string   `json:"jwks_uri"`
	// RegistrationEndpoint is required by MCP Auth spec so clients can dynamically
	// register and obtain a client_id (RFC 7591).
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

func NewMetadataHandler(issuer string) http.HandlerFunc {
	metadata := ServerMetadata{
		Issuer:                        issuer,
		AuthorizationEndpoint:         issuer + "/authorize",
		TokenEndpoint:                 issuer + "/token",
		RevocationEndpoint:            issuer + "/revoke",
		JWKSUri:                       issuer + "/.well-known/jwks.json",
		RegistrationEndpoint:          issuer + "/register",
		ResponseTypesSupported:        []string{"code"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported: []string{"S256"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
}