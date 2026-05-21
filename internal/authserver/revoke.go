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

		hint := r.FormValue("token_type_hint")

		// RFC 7009 §2.1: if hint is given, try that type first, then fall back.
		// RFC 7009 §2.2: always return 200 regardless of whether token existed.
		switch hint {
		case "access_token":
			store.DeleteAccessToken(token)
			store.DeleteRefreshToken(token)
		case "refresh_token":
			store.DeleteRefreshToken(token)
			store.DeleteAccessToken(token)
		default:
			store.DeleteAccessToken(token)
			store.DeleteRefreshToken(token)
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	}
}
