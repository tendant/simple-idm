package logins

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

// FileLoginsRepository implements LoginsRepository using file-based storage
type FileLoginsRepository struct {
	dataDir string
	logins  map[uuid.UUID]LoginEntity
	mutex   sync.RWMutex
}

// NewFileLoginsRepository creates a new file-based logins repository
func NewFileLoginsRepository(dataDir string) (*FileLoginsRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileLoginsRepository{
		dataDir: dataDir,
		logins:  make(map[uuid.UUID]LoginEntity),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// GetLogin retrieves a login by ID
func (r *FileLoginsRepository) GetLogin(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[id]
	if !exists {
		return LoginEntity{}, fmt.Errorf("login not found: %s", id)
	}

	// Don't return soft-deleted logins
	if login.DeletedAtValid {
		return LoginEntity{}, fmt.Errorf("login not found: %s", id)
	}

	return login, nil
}

// GetLoginByUsername retrieves a login by username
func (r *FileLoginsRepository) GetLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error) {
	if !usernameValid || username == "" {
		return LoginEntity{}, fmt.Errorf("invalid username")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, login := range r.logins {
		if login.UsernameValid && login.Username == username && !login.DeletedAtValid {
			return login, nil
		}
	}

	return LoginEntity{}, fmt.Errorf("login not found with username: %s", username)
}

// ListLogins retrieves a list of logins with pagination
func (r *FileLoginsRepository) ListLogins(ctx context.Context, params ListLoginsParams) ([]LoginEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Filter non-deleted logins
	var logins []LoginEntity
	for _, login := range r.logins {
		if !login.DeletedAtValid {
			logins = append(logins, login)
		}
	}

	// Sort by created_at desc (most recent first)
	// Simple bubble sort for now
	for i := 0; i < len(logins); i++ {
		for j := i + 1; j < len(logins); j++ {
			if logins[i].CreatedAt.Before(logins[j].CreatedAt) {
				logins[i], logins[j] = logins[j], logins[i]
			}
		}
	}

	// Apply pagination
	start := int(params.Offset)
	end := start + int(params.Limit)

	if start >= len(logins) {
		return []LoginEntity{}, nil
	}

	if end > len(logins) {
		end = len(logins)
	}

	return logins[start:end], nil
}

// CountLogins returns the total number of logins
func (r *FileLoginsRepository) CountLogins(ctx context.Context) (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	count := int64(0)
	for _, login := range r.logins {
		if !login.DeletedAtValid {
			count++
		}
	}

	return count, nil
}

// SearchLogins searches for logins by username pattern
func (r *FileLoginsRepository) SearchLogins(ctx context.Context, params SearchLoginsParams) ([]LoginEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	query := strings.ToLower(params.Query)
	var results []LoginEntity

	for _, login := range r.logins {
		if login.DeletedAtValid {
			continue
		}

		if login.UsernameValid && strings.Contains(strings.ToLower(login.Username), query) {
			results = append(results, login)
		}
	}

	// Sort by created_at desc
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].CreatedAt.Before(results[j].CreatedAt) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	// Apply pagination
	start := int(params.Offset)
	end := start + int(params.Limit)

	if start >= len(results) {
		return []LoginEntity{}, nil
	}

	if end > len(results) {
		end = len(results)
	}

	return results[start:end], nil
}

// CreateLogin creates a new login
func (r *FileLoginsRepository) CreateLogin(ctx context.Context, params CreateLoginParams) (LoginEntity, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login := LoginEntity{
		ID:             uuid.New(),
		Username:       params.Username,
		UsernameValid:  params.UsernameValid,
		Password:       params.Password,
		CreatedBy:      params.CreatedBy,
		CreatedByValid: params.CreatedByValid,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	r.logins[login.ID] = login

	if err := r.save(); err != nil {
		// Rollback
		delete(r.logins, login.ID)
		return LoginEntity{}, fmt.Errorf("failed to save: %w", err)
	}

	return login, nil
}

// UpdateLogin updates a login's username
func (r *FileLoginsRepository) UpdateLogin(ctx context.Context, params UpdateLoginParams) (LoginEntity, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[params.ID]
	if !exists || login.DeletedAtValid {
		return LoginEntity{}, fmt.Errorf("login not found: %s", params.ID)
	}

	// Update fields
	login.Username = params.Username
	login.UsernameValid = params.UsernameValid
	login.UpdatedAt = time.Now().UTC()

	r.logins[params.ID] = login

	if err := r.save(); err != nil {
		return LoginEntity{}, fmt.Errorf("failed to save: %w", err)
	}

	return login, nil
}

// DeleteLogin soft deletes a login
func (r *FileLoginsRepository) DeleteLogin(ctx context.Context, id uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[id]
	if !exists {
		return fmt.Errorf("login not found: %s", id)
	}

	// Soft delete
	login.DeletedAt = time.Now().UTC()
	login.DeletedAtValid = true
	login.UpdatedAt = time.Now().UTC()

	r.logins[id] = login

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// WithTx returns a new repository with the given transaction
// File-based implementation doesn't support transactions, returns self
func (r *FileLoginsRepository) WithTx(tx interface{}) LoginsRepository {
	// File-based storage doesn't support transactions
	// Return self to maintain interface compatibility
	return r
}

// load reads logins data from file
func (r *FileLoginsRepository) load() error {
	filePath := filepath.Join(r.dataDir, "logins.json")

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

	var logins []LoginEntity
	if err := json.Unmarshal(data, &logins); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to map
	r.logins = make(map[uuid.UUID]LoginEntity)
	for _, login := range logins {
		r.logins[login.ID] = login
	}

	return nil
}

// save writes logins data to file atomically
func (r *FileLoginsRepository) save() error {
	// Convert map to slice
	logins := make([]LoginEntity, 0, len(r.logins))
	for _, login := range r.logins {
		logins = append(logins, login)
	}

	data, err := json.MarshalIndent(logins, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "logins.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "logins.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
