package authserver

import (
	"net/http"
)

func NewRevokeHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse form", http.StatusBadRequest)
			return
		}

		token := r.FormValue("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		// Access tokens are JWTs — stateless, cannot be revoked via store.
		// Only refresh tokens are stored and can be revoked.
		// RFC 7009 §2.2: always return 200 regardless of whether token existed.
		store.DeleteRefreshToken(token)

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	}
}
