package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// fileProfileData represents all profile data stored in the file
type fileProfileData struct {
	Users  map[uuid.UUID]Profile      `json:"users"`  // keyed by user ID
	Logins map[uuid.UUID]LoginRecord  `json:"logins"` // keyed by login ID
	Phones map[uuid.UUID]string       `json:"phones"` // user ID -> phone number
}

// FileProfileRepository implements ProfileRepository using file-based storage
type FileProfileRepository struct {
	dataDir string
	data    *fileProfileData
	mutex   sync.RWMutex
}

// NewFileProfileRepository creates a new file-based profile repository
func NewFileProfileRepository(dataDir string) (*FileProfileRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileProfileRepository{
		dataDir: dataDir,
		data: &fileProfileData{
			Users:  make(map[uuid.UUID]Profile),
			Logins: make(map[uuid.UUID]LoginRecord),
			Phones: make(map[uuid.UUID]string),
		},
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// GetUserById retrieves a user by their ID
func (r *FileProfileRepository) GetUserById(ctx context.Context, id uuid.UUID) (Profile, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.data.Users[id]
	if !exists {
		return Profile{}, fmt.Errorf("user not found: %s", id)
	}

	return user, nil
}

// GetLoginById retrieves a login by its ID
func (r *FileProfileRepository) GetLoginById(ctx context.Context, id uuid.UUID) (LoginRecord, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.data.Logins[id]
	if !exists {
		return LoginRecord{}, fmt.Errorf("login not found: %s", id)
	}

	return login, nil
}

// FindUserByUsername finds users by their username
func (r *FileProfileRepository) FindUserByUsername(ctx context.Context, username string) ([]Profile, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var users []Profile
	usernameLower := strings.ToLower(username)

	for _, user := range r.data.Users {
		if strings.ToLower(user.Username) == usernameLower {
			users = append(users, user)
		}
	}

	return users, nil
}

// UpdateUsername updates a user's username
func (r *FileProfileRepository) UpdateUsername(ctx context.Context, arg UpdateUsernameParam) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.data.Users[arg.ID]
	if !exists {
		return fmt.Errorf("user not found: %s", arg.ID)
	}

	// Update username
	user.Username = arg.Username
	user.LastModifiedAt = time.Now().UTC()

	r.data.Users[arg.ID] = user

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// UpdateLoginId updates a user's login ID
func (r *FileProfileRepository) UpdateLoginId(ctx context.Context, arg UpdateLoginIdParam) (uuid.UUID, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.data.Users[arg.ID]
	if !exists {
		return uuid.Nil, fmt.Errorf("user not found: %s", arg.ID)
	}

	// Update login ID
	if arg.LoginID.Valid {
		user.LoginID = arg.LoginID.UUID
	} else {
		user.LoginID = uuid.Nil
	}
	user.LastModifiedAt = time.Now().UTC()

	r.data.Users[arg.ID] = user

	if err := r.save(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to save: %w", err)
	}

	return user.LoginID, nil
}

// GetUserPhone gets a user's phone number
func (r *FileProfileRepository) GetUserPhone(ctx context.Context, id uuid.UUID) (string, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	phone, exists := r.data.Phones[id]
	if !exists {
		return "", nil // Return empty string if no phone found
	}

	return phone, nil
}

// UpdateUserPhone updates a user's phone number
func (r *FileProfileRepository) UpdateUserPhone(ctx context.Context, arg UpdatePhoneParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Verify user exists
	if _, exists := r.data.Users[arg.ID]; !exists {
		return fmt.Errorf("user not found: %s", arg.ID)
	}

	// Update phone
	if arg.Phone == "" {
		delete(r.data.Phones, arg.ID)
	} else {
		r.data.Phones[arg.ID] = arg.Phone
	}

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// load reads profile data from file
func (r *FileProfileRepository) load() error {
	filePath := filepath.Join(r.dataDir, "profile.json")

	// If file doesn't exist, start with empty data
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty data
	if len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, r.data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// save writes profile data to file atomically
func (r *FileProfileRepository) save() error {
	data, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "profile.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "profile.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
