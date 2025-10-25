package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileOIDCRepository implements OIDCRepository using file-based storage
type FileOIDCRepository struct {
	dataDir   string
	authCodes map[string]*AuthorizationCode
	sessions  map[string]*OIDCSession
	mutex     sync.RWMutex
}

// oidcData represents the structure of data stored in the JSON file
type oidcData struct {
	AuthCodes []*AuthorizationCode `json:"auth_codes"`
	Sessions  []*OIDCSession       `json:"sessions"`
}

// NewFileOIDCRepository creates a new file-based OIDC repository
func NewFileOIDCRepository(dataDir string) (*FileOIDCRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileOIDCRepository{
		dataDir:   dataDir,
		authCodes: make(map[string]*AuthorizationCode),
		sessions:  make(map[string]*OIDCSession),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// StoreAuthorizationCode stores an authorization code
func (r *FileOIDCRepository) StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
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

	// Store the code (make a copy)
	r.authCodes[code.Code] = &AuthorizationCode{
		Code:                code.Code,
		ClientID:            code.ClientID,
		RedirectURI:         code.RedirectURI,
		Scope:               code.Scope,
		State:               code.State,
		UserID:              code.UserID,
		ExpiresAt:           code.ExpiresAt,
		Used:                code.Used,
		CreatedAt:           code.CreatedAt,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
	}

	// Persist to file
	return r.save()
}

// GetAuthorizationCode retrieves an authorization code
func (r *FileOIDCRepository) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
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
		Code:                authCode.Code,
		ClientID:            authCode.ClientID,
		RedirectURI:         authCode.RedirectURI,
		Scope:               authCode.Scope,
		State:               authCode.State,
		UserID:              authCode.UserID,
		ExpiresAt:           authCode.ExpiresAt,
		Used:                authCode.Used,
		CreatedAt:           authCode.CreatedAt,
		CodeChallenge:       authCode.CodeChallenge,
		CodeChallengeMethod: authCode.CodeChallengeMethod,
	}, nil
}

// MarkAuthorizationCodeUsed marks an authorization code as used
func (r *FileOIDCRepository) MarkAuthorizationCodeUsed(ctx context.Context, code string) error {
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

	// Persist to file
	return r.save()
}

// StoreSession stores an OIDC session
func (r *FileOIDCRepository) StoreSession(ctx context.Context, session *OIDCSession) error {
	if session == nil {
		return errors.New("session cannot be nil")
	}

	if session.ID == "" {
		return errors.New("session ID cannot be empty")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Store the session (make a copy)
	r.sessions[session.ID] = &OIDCSession{
		ID:        session.ID,
		UserID:    session.UserID,
		ClientID:  session.ClientID,
		Scope:     session.Scope,
		CreatedAt: session.CreatedAt,
		ExpiresAt: session.ExpiresAt,
	}

	// Persist to file
	return r.save()
}

// GetSession retrieves an OIDC session
func (r *FileOIDCRepository) GetSession(ctx context.Context, sessionID string) (*OIDCSession, error) {
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
	if time.Now().UTC().After(session.ExpiresAt) {
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
// File-based implementation doesn't support transactions, returns self
func (r *FileOIDCRepository) WithTx(tx interface{}) OIDCRepository {
	// File-based storage doesn't support transactions
	// Return self to maintain interface compatibility
	return r
}

// load reads OIDC data from file
func (r *FileOIDCRepository) load() error {
	filePath := filepath.Join(r.dataDir, "oidc.json")

	// If file doesn't exist, start with empty maps
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty maps
	if len(data) == 0 {
		return nil
	}

	var oidcData oidcData
	if err := json.Unmarshal(data, &oidcData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to maps
	r.authCodes = make(map[string]*AuthorizationCode)
	for _, code := range oidcData.AuthCodes {
		r.authCodes[code.Code] = code
	}

	r.sessions = make(map[string]*OIDCSession)
	for _, session := range oidcData.Sessions {
		r.sessions[session.ID] = session
	}

	return nil
}

// save writes OIDC data to file atomically
func (r *FileOIDCRepository) save() error {
	// Convert maps to slices
	authCodes := make([]*AuthorizationCode, 0, len(r.authCodes))
	for _, code := range r.authCodes {
		authCodes = append(authCodes, code)
	}

	sessions := make([]*OIDCSession, 0, len(r.sessions))
	for _, session := range r.sessions {
		sessions = append(sessions, session)
	}

	data := oidcData{
		AuthCodes: authCodes,
		Sessions:  sessions,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "oidc.json.tmp")
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "oidc.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
