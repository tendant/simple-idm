package emailverification

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EmailVerificationRepository defines the interface for email verification operations
type EmailVerificationRepository interface {
	CreateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*VerificationToken, error)
	GetVerificationTokenByToken(ctx context.Context, token string) (*VerificationToken, error)
	GetActiveTokensByUserId(ctx context.Context, userID uuid.UUID) ([]*VerificationToken, error)
	MarkTokenAsVerified(ctx context.Context, tokenID uuid.UUID) error
	SoftDeleteToken(ctx context.Context, tokenID uuid.UUID) error
	SoftDeleteUserTokens(ctx context.Context, userID uuid.UUID) error
	MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error
	GetUserEmailVerificationStatus(ctx context.Context, userID uuid.UUID) (*UserEmailStatus, error)
	CountRecentTokensByUserId(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error)
	CleanupExpiredTokens(ctx context.Context) error
	GetUserByEmail(ctx context.Context, email string) (*UserEmailStatus, error)
}

// FileEmailVerificationRepository implements EmailVerificationRepository using file-based storage
type FileEmailVerificationRepository struct {
	dataDir string
	tokens  map[uuid.UUID]*VerificationToken // Key: token ID
	users   map[uuid.UUID]*UserEmailStatus   // Key: user ID
	mutex   sync.RWMutex
}

// emailVerificationData represents the structure of data stored in the JSON file
type emailVerificationData struct {
	Tokens []*VerificationToken `json:"tokens"`
	Users  []*UserEmailStatus   `json:"users"`
}

// NewFileEmailVerificationRepository creates a new file-based email verification repository
func NewFileEmailVerificationRepository(dataDir string) (*FileEmailVerificationRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileEmailVerificationRepository{
		dataDir: dataDir,
		tokens:  make(map[uuid.UUID]*VerificationToken),
		users:   make(map[uuid.UUID]*UserEmailStatus),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// CreateVerificationToken creates a new verification token
func (r *FileEmailVerificationRepository) CreateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*VerificationToken, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	vt := &VerificationToken{
		ID:         uuid.New(),
		UserID:     userID,
		Token:      token,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  expiresAt,
		VerifiedAt: nil,
		DeletedAt:  nil,
	}

	r.tokens[vt.ID] = vt

	if err := r.save(); err != nil {
		delete(r.tokens, vt.ID)
		return nil, fmt.Errorf("failed to save: %w", err)
	}

	return vt, nil
}

// GetVerificationTokenByToken retrieves an active verification token
func (r *FileEmailVerificationRepository) GetVerificationTokenByToken(ctx context.Context, token string) (*VerificationToken, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, vt := range r.tokens {
		if vt.Token == token && vt.DeletedAt == nil && vt.VerifiedAt == nil {
			vtCopy := *vt
			return &vtCopy, nil
		}
	}

	return nil, fmt.Errorf("verification token not found")
}

// GetActiveTokensByUserId retrieves all active verification tokens for a user
func (r *FileEmailVerificationRepository) GetActiveTokensByUserId(ctx context.Context, userID uuid.UUID) ([]*VerificationToken, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var tokens []*VerificationToken
	for _, vt := range r.tokens {
		if vt.UserID == userID && vt.DeletedAt == nil && vt.VerifiedAt == nil {
			vtCopy := *vt
			tokens = append(tokens, &vtCopy)
		}
	}

	return tokens, nil
}

// MarkTokenAsVerified marks a token as verified
func (r *FileEmailVerificationRepository) MarkTokenAsVerified(ctx context.Context, tokenID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	vt, exists := r.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token not found")
	}

	now := time.Now().UTC()
	vt.VerifiedAt = &now

	return r.save()
}

// SoftDeleteToken soft deletes a verification token
func (r *FileEmailVerificationRepository) SoftDeleteToken(ctx context.Context, tokenID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	vt, exists := r.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token not found")
	}

	now := time.Now().UTC()
	vt.DeletedAt = &now

	return r.save()
}

// SoftDeleteUserTokens soft deletes all tokens for a user
func (r *FileEmailVerificationRepository) SoftDeleteUserTokens(ctx context.Context, userID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now().UTC()
	for _, vt := range r.tokens {
		if vt.UserID == userID {
			vt.DeletedAt = &now
		}
	}

	return r.save()
}

// MarkUserEmailAsVerified marks a user's email as verified
func (r *FileEmailVerificationRepository) MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.users[userID]
	if !exists {
		// Create user status if it doesn't exist
		user = &UserEmailStatus{
			ID:            userID,
			EmailVerified: true,
		}
		r.users[userID] = user
	} else {
		user.EmailVerified = true
	}

	now := time.Now().UTC()
	user.EmailVerifiedAt = &now

	return r.save()
}

// GetUserEmailVerificationStatus gets a user's email verification status
func (r *FileEmailVerificationRepository) GetUserEmailVerificationStatus(ctx context.Context, userID uuid.UUID) (*UserEmailStatus, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	userCopy := *user
	return &userCopy, nil
}

// CountRecentTokensByUserId counts recent tokens for a user since a given time
func (r *FileEmailVerificationRepository) CountRecentTokensByUserId(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	count := int64(0)
	for _, vt := range r.tokens {
		if vt.UserID == userID && vt.CreatedAt.After(since) {
			count++
		}
	}

	return count, nil
}

// CleanupExpiredTokens removes expired tokens
func (r *FileEmailVerificationRepository) CleanupExpiredTokens(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now().UTC()
	for tokenID, vt := range r.tokens {
		if now.After(vt.ExpiresAt) {
			vt.DeletedAt = &now
			// Optionally: delete(r.tokens, tokenID) to completely remove
		}
		_ = tokenID // Keep in map but mark as deleted
	}

	return r.save()
}

// GetUserByEmail retrieves a user by email
// Note: This method requires access to user data which is typically stored elsewhere
func (r *FileEmailVerificationRepository) GetUserByEmail(ctx context.Context, email string) (*UserEmailStatus, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, user := range r.users {
		if user.Email == email {
			userCopy := *user
			return &userCopy, nil
		}
	}

	return nil, fmt.Errorf("user not found with email: %s", email)
}

// load reads email verification data from file
func (r *FileEmailVerificationRepository) load() error {
	filePath := filepath.Join(r.dataDir, "email_verification.json")

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

	var evData emailVerificationData
	if err := json.Unmarshal(data, &evData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to maps
	r.tokens = make(map[uuid.UUID]*VerificationToken)
	for _, token := range evData.Tokens {
		r.tokens[token.ID] = token
	}

	r.users = make(map[uuid.UUID]*UserEmailStatus)
	for _, user := range evData.Users {
		r.users[user.ID] = user
	}

	return nil
}

// save writes email verification data to file atomically
func (r *FileEmailVerificationRepository) save() error {
	// Convert maps to slices
	tokens := make([]*VerificationToken, 0, len(r.tokens))
	for _, token := range r.tokens {
		tokens = append(tokens, token)
	}

	users := make([]*UserEmailStatus, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	data := emailVerificationData{
		Tokens: tokens,
		Users:  users,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "email_verification.json.tmp")
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "email_verification.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
