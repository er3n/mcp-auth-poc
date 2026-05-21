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
		handleAuthorizeForm(w, r)
	}
}

func handleAuthorizeForm(w http.ResponseWriter, r *http.Request) {
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

	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
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
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	})

	redirectURL := redirectURI + "?code=" + code
	if state != "" {
		redirectURL += "&state=" + state
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
