package authserver

import (
	"sync"
	"time"
)

type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Subject             string
	ExpiresAt           time.Time
}

// RefreshTokenInfo is stored server-side to support rotation + replay detection.
// Access tokens are JWTs — self-contained, no server-side storage needed.
type RefreshTokenInfo struct {
	Token     string
	ClientID  string
	Subject   string
	Scope     string
	ExpiresAt time.Time
}

// ClientInfo holds a dynamically registered OAuth client (RFC 7591).
// We only support public clients (no client_secret) — appropriate for MCP desktop apps.
type ClientInfo struct {
	ClientID     string
	RedirectURIs []string
	Name         string
	CreatedAt    time.Time
}

type Store struct {
	mu            sync.RWMutex
	codes         map[string]AuthCode
	refreshTokens map[string]RefreshTokenInfo
	clients       map[string]ClientInfo
}

func NewStore() *Store {
	return &Store{
		codes:         make(map[string]AuthCode),
		refreshTokens: make(map[string]RefreshTokenInfo),
		clients:       make(map[string]ClientInfo),
	}
}

func (s *Store) SaveCode(code AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
}

func (s *Store) GetCode(code string) (AuthCode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.codes[code]
	return c, ok
}

func (s *Store) DeleteCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
}

func (s *Store) SaveRefreshToken(t RefreshTokenInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[t.Token] = t
}

func (s *Store) GetRefreshToken(token string) (RefreshTokenInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.refreshTokens[token]
	return t, ok
}

// DeleteRefreshToken is called on rotation — old token is consumed, new one issued.
func (s *Store) DeleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}

func (s *Store) RegisterClient(c ClientInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
}

func (s *Store) GetClient(clientID string) (ClientInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	return c, ok
}
