// DefaultSession is a default implementation of the session interface.
package oidc

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
)

type DefaultSession struct {
	ExpiresAt map[fosite.TokenType]time.Time `json:"exp"`
	Username  string                         `json:"username"`
	Subject   string                         `json:"sub"`
	Extra     map[string]interface{}         `json:"extra"`
}

func (s *DefaultSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

func (s *DefaultSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}

	return s.ExpiresAt[key]
}

func (s *DefaultSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

func (s *DefaultSession) SetSubject(subject string) {
	s.Subject = subject
}

func (s *DefaultSession) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject
}

func (s *DefaultSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(fosite.Session)
}

// ExtraClaimsSession provides an interface for session to store any extra claims.
type ExtraClaimsSession interface {
	// GetExtraClaims returns a map to store extra claims.
	// The returned value can be modified in-place.
	GetExtraClaims() map[string]interface{}
}

// GetExtraClaims implements ExtraClaimsSession for DefaultSession.
// The returned value can be modified in-place.
func (s *DefaultSession) GetExtraClaims() map[string]interface{} {
	if s == nil {
		return nil
	}

	if s.Extra == nil {
		s.Extra = make(map[string]interface{})
	}

	return s.Extra
}
