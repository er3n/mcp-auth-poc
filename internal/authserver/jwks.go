package authserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

// KeyPair holds the RSA key pair used to sign and verify JWT access tokens.
// Private key stays on the auth server; public key is exposed via JWKS.
type KeyPair struct {
	Private *rsa.PrivateKey
	// kid (key ID) lets clients cache multiple keys and rotate without breakage.
	// RFC 7517 §4.5
	KID string
}

func GenerateKeyPair() (*KeyPair, error) {
	// 2048-bit RSA is the minimum recommended by current NIST guidance.
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Private: private,
		KID:     "key-1",
	}, nil
}

// NewJWKSHandler exposes the public key in JWKS format (RFC 7517).
// Resource servers fetch this endpoint to verify JWT signatures locally —
// no need to call the auth server on every request.
func NewJWKSHandler(kp *KeyPair) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub := kp.Private.Public().(*rsa.PublicKey)

		// JWK (JSON Web Key) RSA public key fields — RFC 7517 + RFC 7518 §6.3
		// n = modulus, e = exponent, both base64url-encoded big integers
		jwk := map[string]any{
			"kty": "RSA",   // key type
			"use": "sig",   // usage: signature verification
			"alg": "RS256", // algorithm
			"kid": kp.KID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{jwk},
		})
	}
}
