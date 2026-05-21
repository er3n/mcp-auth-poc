package authserver

import (
	"encoding/json"
	"net/http"
)

func NewUserInfoHandler(kp *KeyPair) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := ExtractBearer(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := ParseJWT(tokenStr, kp)
		if err != nil {
			// RFC 6750 §3.1: invalid or expired token → 401 with WWW-Authenticate
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	}
}
