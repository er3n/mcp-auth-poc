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

type Store struct {
	mu    sync.RWMutex
	codes map[string]AuthCode
}

func NewStore() *Store {
	return &Store{
		codes: make(map[string]AuthCode),
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
