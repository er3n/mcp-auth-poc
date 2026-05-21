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
	ExpiresAt           time.Time
}

// AccessTokenInfo holds metadata for a issued access token.
// In production you'd use JWT — opaque tokens require server-side lookup.
type AccessTokenInfo struct {
	Token     string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
}

// RefreshTokenInfo is stored server-side to support rotation + replay detection.
type RefreshTokenInfo struct {
	Token     string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
}

type Store struct {
	mu            sync.RWMutex
	codes         map[string]AuthCode
	accessTokens  map[string]AccessTokenInfo
	refreshTokens map[string]RefreshTokenInfo
}

func NewStore() *Store {
	return &Store{
		codes:         make(map[string]AuthCode),
		accessTokens:  make(map[string]AccessTokenInfo),
		refreshTokens: make(map[string]RefreshTokenInfo),
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

func (s *Store) SaveAccessToken(t AccessTokenInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[t.Token] = t
}

func (s *Store) GetAccessToken(token string) (AccessTokenInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.accessTokens[token]
	return t, ok
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

func (s *Store) DeleteAccessToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, token)
}

// DeleteRefreshToken is called on rotation — old token is consumed, new one issued.
func (s *Store) DeleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}
