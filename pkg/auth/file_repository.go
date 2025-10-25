package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

// FileAuthRepository implements AuthRepository using file-based storage
type FileAuthRepository struct {
	dataDir string
	users   map[uuid.UUID]UserAuthEntity // keyed by user UUID
	mutex   sync.RWMutex
}

// NewFileAuthRepository creates a new file-based auth repository
func NewFileAuthRepository(dataDir string) (*FileAuthRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileAuthRepository{
		dataDir: dataDir,
		users:   make(map[uuid.UUID]UserAuthEntity),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// FindUserByUserUUID retrieves user authentication data by user UUID
func (r *FileAuthRepository) FindUserByUserUUID(ctx context.Context, userUUID uuid.UUID) (UserAuthEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[userUUID]
	if !exists {
		return UserAuthEntity{}, fmt.Errorf("user not found: %s", userUUID)
	}

	return user, nil
}

// UpdatePassword updates a user's password
func (r *FileAuthRepository) UpdatePassword(ctx context.Context, params UpdatePasswordParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.users[params.UserID]
	if !exists {
		return fmt.Errorf("user not found: %s", params.UserID)
	}

	// Update password
	user.Password = params.Password
	user.PasswordValid = true

	r.users[params.UserID] = user

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// load reads user authentication data from file
func (r *FileAuthRepository) load() error {
	filePath := filepath.Join(r.dataDir, "auth.json")

	// If file doesn't exist, start with empty map
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty map
	if len(data) == 0 {
		return nil
	}

	var users []UserAuthEntity
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to map
	r.users = make(map[uuid.UUID]UserAuthEntity)
	for _, user := range users {
		r.users[user.UUID] = user
	}

	return nil
}

// save writes user authentication data to file atomically
func (r *FileAuthRepository) save() error {
	// Convert map to slice
	users := make([]UserAuthEntity, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "auth.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "auth.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
