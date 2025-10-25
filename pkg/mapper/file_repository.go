package mapper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// FileMapperRepository implements MapperRepository using file-based storage
type FileMapperRepository struct {
	dataDir string
	users   map[uuid.UUID]UserEntity // keyed by user ID
	mutex   sync.RWMutex
}

// NewFileMapperRepository creates a new file-based mapper repository
func NewFileMapperRepository(dataDir string) (*FileMapperRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileMapperRepository{
		dataDir: dataDir,
		users:   make(map[uuid.UUID]UserEntity),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// GetUsersByLoginID retrieves all users linked to a login ID
func (r *FileMapperRepository) GetUsersByLoginID(ctx context.Context, loginID uuid.UUID, includeGroups bool) ([]UserEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var users []UserEntity
	for _, user := range r.users {
		if user.LoginIDValid && user.LoginID == loginID {
			// Clone the user to avoid returning internal references
			userCopy := user
			if !includeGroups {
				// Clear groups and roles if not requested
				userCopy.Groups = nil
				userCopy.Roles = nil
			}
			users = append(users, userCopy)
		}
	}

	return users, nil
}

// GetUserByUserID retrieves a user by user ID
func (r *FileMapperRepository) GetUserByUserID(ctx context.Context, userID uuid.UUID, includeGroups bool) (UserEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[userID]
	if !exists {
		return UserEntity{}, fmt.Errorf("user not found: %s", userID)
	}

	// Clone the user to avoid returning internal references
	userCopy := user
	if !includeGroups {
		// Clear groups and roles if not requested
		userCopy.Groups = nil
		userCopy.Roles = nil
	}

	return userCopy, nil
}

// FindUsernamesByEmail retrieves all usernames associated with an email
func (r *FileMapperRepository) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var usernames []string
	emailLower := strings.ToLower(email)

	for _, user := range r.users {
		if strings.ToLower(user.Email) == emailLower {
			if user.NameValid && user.Name != "" {
				usernames = append(usernames, user.Name)
			}
		}
	}

	return usernames, nil
}

// load reads user data from file
func (r *FileMapperRepository) load() error {
	filePath := filepath.Join(r.dataDir, "mapper.json")

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

	var users []UserEntity
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to map
	r.users = make(map[uuid.UUID]UserEntity)
	for _, user := range users {
		r.users[user.ID] = user
	}

	return nil
}

// save writes user data to file atomically
func (r *FileMapperRepository) save() error {
	// Convert map to slice
	users := make([]UserEntity, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "mapper.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "mapper.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
