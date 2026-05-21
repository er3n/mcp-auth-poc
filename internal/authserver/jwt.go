package authserver

import (
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
func ExtractBearer(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" || !strings.HasPrefix(header, "Bearer ") {
		return "", ErrMissingToken
	}
	return strings.TrimPrefix(header, "Bearer "), nil
}

// ParseJWT validates the token signature and expiry, returns the claims.
func ParseJWT(tokenStr string, kp *KeyPair) (jwt.MapClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		// Reject tokens that aren't signed with RS256 — prevents "alg:none" attacks.
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidToken
		}
		return &kp.Private.PublicKey, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
