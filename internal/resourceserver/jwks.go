package resourceserver

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

// A JWK RSA public key contains two fields:
//   n — the modulus (a large integer, base64url-encoded)
//   e — the public exponent (almost always 65537, base64url-encoded)
//
// Together they form an rsa.PublicKey. This struct is just for JSON parsing.
type jwksResponse struct {
	Keys []struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"keys"`
}

// FetchPublicKey fetches the RSA public key from the AS's JWKS endpoint and
// reconstructs it into a *rsa.PublicKey for local JWT verification.
//
// Call this once at startup — the key rarely rotates, so caching in memory is fine.
// In production you'd also handle key rotation by re-fetching when a token references
// an unknown kid (key ID).
func FetchPublicKey(jwksURL string) (*rsa.PublicKey, error) {
	// In Go, http.Get sends a GET request and returns *http.Response + error.
	// Always close resp.Body to release the TCP connection.
	resp, err := http.Get(jwksURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys in jwks response")
	}

	key := jwks.Keys[0]

	// base64.RawURLEncoding = base64url without padding ('=' chars) — standard for JWK.
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode jwk n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode jwk e: %w", err)
	}

	// big.Int.SetBytes interprets the byte slice as a big-endian unsigned integer.
	// RSA public key = (N, E) where N is a ~2048-bit number that doesn't fit in int64.
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	return pub, nil
}
