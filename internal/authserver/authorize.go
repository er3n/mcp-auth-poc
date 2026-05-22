package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

	client, err := resolveClient(clientID, store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

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

	client, err := resolveClient(clientID, store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
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

// resolveClient looks up a client by ID. If the client_id is an HTTPS URL,
// it follows the CIMD path (MCP Auth spec): fetch the metadata document from
// that URL and cache the result in the store for subsequent requests.
// Otherwise it falls back to the DCR store (POST /register path).
func resolveClient(clientID string, store *Store) (ClientInfo, error) {
	// Fast path: already in store (DCR-registered or previously cached CIMD).
	if client, ok := store.GetClient(clientID); ok {
		return client, nil
	}

	// CIMD path: client_id must be an HTTPS URL.
	if !strings.HasPrefix(clientID, "https://") {
		return ClientInfo{}, fmt.Errorf("unknown client_id")
	}

	resp, err := http.Get(clientID) //nolint:noctx
	if err != nil {
		return ClientInfo{}, fmt.Errorf("failed to fetch client metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ClientInfo{}, fmt.Errorf("client metadata fetch returned %d", resp.StatusCode)
	}

	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return ClientInfo{}, fmt.Errorf("invalid client metadata JSON: %w", err)
	}

	// The client_id in the document must match the URL we fetched from.
	// This prevents a server at URL A from claiming to be client B.
	if doc.ClientID != clientID {
		return ClientInfo{}, fmt.Errorf("client_id in metadata (%s) does not match fetch URL", doc.ClientID)
	}

	if len(doc.RedirectURIs) == 0 {
		return ClientInfo{}, fmt.Errorf("client metadata has no redirect_uris")
	}

	client := ClientInfo{
		ClientID:     clientID,
		RedirectURIs: doc.RedirectURIs,
		Name:         doc.ClientName,
		CreatedAt:    time.Now(),
	}
	store.RegisterClient(client)
	return client, nil
}

// containsURI checks whether target matches any URI in the list.
// For loopback addresses (localhost / 127.0.0.1 / [::1]) the port is ignored
// per RFC 8252 §7.3 — native apps bind an ephemeral port at runtime, but the
// CIMD document only lists the base URI without a port.
func containsURI(uris []string, target string) bool {
	for _, u := range uris {
		if u == target {
			return true
		}
		if isLoopback(u) && isLoopback(target) && stripPort(u) == stripPort(target) {
			return true
		}
	}
	return false
}

func isLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func stripPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Host = u.Hostname()
	return u.String()
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
