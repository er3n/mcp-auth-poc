package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

func NewAuthorizeHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleAuthorizeConfirm(w, r, store)
			return
		}
		handleAuthorizeForm(w, r, store)
	}
}

func handleAuthorizeForm(w http.ResponseWriter, r *http.Request, store *Store) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	responseType := q.Get("response_type")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	scope := q.Get("scope")

	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod != "S256" {
		http.Error(w, "unsupported code_challenge_method, use S256", http.StatusBadRequest)
		return
	}

	// RFC 7591: only registered clients may initiate authorization.
	client, ok := store.GetClient(clientID)
	if !ok {
		http.Error(w, "unknown client_id — register first via POST /register", http.StatusUnauthorized)
		return
	}

	// OAuth 2.1 §4.1.1: redirect_uri must exactly match a registered URI.
	// This prevents open redirector attacks — attackers can't redirect to their own server.
	if !containsURI(client.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<body>
  <h2>Authorization Request</h2>
  <p><strong>Client:</strong> ` + clientID + `</p>
  <p><strong>Scope:</strong> ` + scope + `</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="` + clientID + `">
    <input type="hidden" name="response_type" value="` + responseType + `">
    <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
    <input type="hidden" name="code_challenge" value="` + codeChallenge + `">
    <input type="hidden" name="code_challenge_method" value="` + codeChallengeMethod + `">
    <input type="hidden" name="state" value="` + state + `">
    <input type="hidden" name="scope" value="` + scope + `">
    <label>Username: <input type="text" name="username" required></label><br>
    <button type="submit">Allow</button>
  </form>
</body>
</html>`))
}

func handleAuthorizeConfirm(w http.ResponseWriter, r *http.Request, store *Store) {
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	state := r.FormValue("state")
	scope := r.FormValue("scope")
	username := r.FormValue("username")

	if clientID == "" || redirectURI == "" || codeChallenge == "" || username == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	// Re-validate on POST too — form values could be tampered.
	client, ok := store.GetClient(clientID)
	if !ok {
		http.Error(w, "unknown client_id", http.StatusUnauthorized)
		return
	}
	if !containsURI(client.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	code, err := generateCode()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	store.SaveCode(AuthCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               scope,
		Subject:             username,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	})

	redirectURL := redirectURI + "?code=" + code
	if state != "" {
		redirectURL += "&state=" + state
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func containsURI(uris []string, target string) bool {
	for _, u := range uris {
		if u == target {
			return true
		}
	}
	return false
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
