package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Domain Models

// AuthorizationCode represents a temporary authorization code (domain model)
type AuthorizationCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	UserID      string
	ExpiresAt   time.Time
	Used        bool
	CreatedAt   time.Time
}

// OIDCSession represents an OIDC session (for future use)
type OIDCSession struct {
	ID        string
	UserID    string
	ClientID  string
	Scope     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Repository Interface

// OIDCRepository defines the interface for OIDC-related database operations
type OIDCRepository interface {
	// Authorization Code operations
	StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, code string) error

	// Session operations (for future use)
	StoreSession(ctx context.Context, session *OIDCSession) error
	GetSession(ctx context.Context, sessionID string) (*OIDCSession, error)

	// Transaction support (for future database implementation)
	WithTx(tx interface{}) OIDCRepository
}

// In-Memory Repository Implementation

// InMemoryOIDCRepository implements OIDCRepository using in-memory storage
type InMemoryOIDCRepository struct {
	authCodes map[string]*AuthorizationCode
	sessions  map[string]*OIDCSession
	mutex     sync.RWMutex
}

// NewInMemoryOIDCRepository creates a new in-memory OIDC repository
func NewInMemoryOIDCRepository() *InMemoryOIDCRepository {
	return &InMemoryOIDCRepository{
		authCodes: make(map[string]*AuthorizationCode),
		sessions:  make(map[string]*OIDCSession),
	}
}

// StoreAuthorizationCode stores an authorization code
func (r *InMemoryOIDCRepository) StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	if code == nil {
		return errors.New("authorization code cannot be nil")
	}

	if code.Code == "" {
		return errors.New("authorization code cannot be empty")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if code already exists
	if _, exists := r.authCodes[code.Code]; exists {
		return fmt.Errorf("authorization code already exists: %s", code.Code)
	}

	// Store the code
	r.authCodes[code.Code] = &AuthorizationCode{
		Code:        code.Code,
		ClientID:    code.ClientID,
		RedirectURI: code.RedirectURI,
		Scope:       code.Scope,
		State:       code.State,
		UserID:      code.UserID,
		ExpiresAt:   code.ExpiresAt,
		Used:        code.Used,
		CreatedAt:   code.CreatedAt,
	}

	return nil
}

// GetAuthorizationCode retrieves an authorization code
func (r *InMemoryOIDCRepository) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	if code == "" {
		return nil, errors.New("authorization code cannot be empty")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	authCode, exists := r.authCodes[code]
	if !exists {
		return nil, fmt.Errorf("authorization code not found: %s", code)
	}

	// Check if expired
	if time.Now().UTC().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired: %s", code)
	}

	// Check if already used
	if authCode.Used {
		return nil, fmt.Errorf("authorization code already used: %s", code)
	}

	// Return a copy to prevent external modification
	return &AuthorizationCode{
		Code:        authCode.Code,
		ClientID:    authCode.ClientID,
		RedirectURI: authCode.RedirectURI,
		Scope:       authCode.Scope,
		State:       authCode.State,
		UserID:      authCode.UserID,
		ExpiresAt:   authCode.ExpiresAt,
		Used:        authCode.Used,
		CreatedAt:   authCode.CreatedAt,
	}, nil
}

// MarkAuthorizationCodeUsed marks an authorization code as used
func (r *InMemoryOIDCRepository) MarkAuthorizationCodeUsed(ctx context.Context, code string) error {
	if code == "" {
		return errors.New("authorization code cannot be empty")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	authCode, exists := r.authCodes[code]
	if !exists {
		return fmt.Errorf("authorization code not found: %s", code)
	}

	// Mark as used
	authCode.Used = true

	return nil
}

// StoreSession stores an OIDC session (for future use)
func (r *InMemoryOIDCRepository) StoreSession(ctx context.Context, session *OIDCSession) error {
	if session == nil {
		return errors.New("session cannot be nil")
	}

	if session.ID == "" {
		return errors.New("session ID cannot be empty")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Store the session
	r.sessions[session.ID] = &OIDCSession{
		ID:        session.ID,
		UserID:    session.UserID,
		ClientID:  session.ClientID,
		Scope:     session.Scope,
		CreatedAt: session.CreatedAt,
		ExpiresAt: session.ExpiresAt,
	}

	return nil
}

// GetSession retrieves an OIDC session (for future use)
func (r *InMemoryOIDCRepository) GetSession(ctx context.Context, sessionID string) (*OIDCSession, error) {
	if sessionID == "" {
		return nil, errors.New("session ID cannot be empty")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	session, exists := r.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired: %s", sessionID)
	}

	// Return a copy to prevent external modification
	return &OIDCSession{
		ID:        session.ID,
		UserID:    session.UserID,
		ClientID:  session.ClientID,
		Scope:     session.Scope,
		CreatedAt: session.CreatedAt,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// WithTx returns a new repository with the given transaction
// For in-memory implementation, this returns self since there are no transactions
func (r *InMemoryOIDCRepository) WithTx(tx interface{}) OIDCRepository {
	// For in-memory implementation, we don't support transactions
	// Just return self
	return r
}
