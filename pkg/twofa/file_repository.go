package twofa

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

// FileTwoFARepository implements TwoFARepository using file-based storage
type FileTwoFARepository struct {
	dataDir  string
	twofas   map[uuid.UUID]TwoFAEntity // keyed by ID
	mutex    sync.RWMutex
}

// NewFileTwoFARepository creates a new file-based 2FA repository
func NewFileTwoFARepository(dataDir string) (*FileTwoFARepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileTwoFARepository{
		dataDir: dataDir,
		twofas:  make(map[uuid.UUID]TwoFAEntity),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// Create2FAInit creates a new 2FA record
func (r *FileTwoFARepository) Create2FAInit(ctx context.Context, params Create2FAParams) (uuid.UUID, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	twofa := TwoFAEntity{
		ID:               uuid.New(),
		LoginID:          params.LoginID,
		TwoFactorSecret:  params.TwoFactorSecret,
		SecretValid:      params.SecretValid,
		TwoFactorType:    params.TwoFactorType,
		TypeValid:        params.TypeValid,
		TwoFactorEnabled: params.TwoFactorEnabled,
		EnabledValid:     params.EnabledValid,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
		UpdatedAtValid:   true,
	}

	r.twofas[twofa.ID] = twofa

	if err := r.save(); err != nil {
		// Rollback
		delete(r.twofas, twofa.ID)
		return uuid.Nil, fmt.Errorf("failed to save: %w", err)
	}

	return twofa.ID, nil
}

// Enable2FA enables 2FA for a login
func (r *FileTwoFARepository) Enable2FA(ctx context.Context, params Enable2FAParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find the 2FA record for this login and type
	for id, twofa := range r.twofas {
		if twofa.LoginID == params.LoginID &&
		   twofa.TypeValid &&
		   twofa.TwoFactorType == params.TwoFactorType {
			twofa.TwoFactorEnabled = true
			twofa.EnabledValid = true
			twofa.UpdatedAt = time.Now().UTC()
			twofa.UpdatedAtValid = true
			r.twofas[id] = twofa

			if err := r.save(); err != nil {
				return fmt.Errorf("failed to save: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("2FA record not found for login %s and type %s", params.LoginID, params.TwoFactorType)
}

// Disable2FA disables 2FA for a login
func (r *FileTwoFARepository) Disable2FA(ctx context.Context, params Disable2FAParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find the 2FA record for this login and type
	for id, twofa := range r.twofas {
		if twofa.LoginID == params.LoginID &&
		   twofa.TypeValid &&
		   twofa.TwoFactorType == params.TwoFactorType {
			twofa.TwoFactorEnabled = false
			twofa.EnabledValid = true
			twofa.UpdatedAt = time.Now().UTC()
			twofa.UpdatedAtValid = true
			r.twofas[id] = twofa

			if err := r.save(); err != nil {
				return fmt.Errorf("failed to save: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("2FA record not found for login %s and type %s", params.LoginID, params.TwoFactorType)
}

// Delete2FA soft deletes a 2FA record
func (r *FileTwoFARepository) Delete2FA(ctx context.Context, params Delete2FAParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find and delete the 2FA record
	for id, twofa := range r.twofas {
		if twofa.ID == params.ID &&
		   twofa.LoginID == params.LoginID &&
		   twofa.TypeValid &&
		   twofa.TwoFactorType == params.TwoFactorType {
			// Hard delete for file-based storage
			delete(r.twofas, id)

			if err := r.save(); err != nil {
				return fmt.Errorf("failed to save: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("2FA record not found")
}

// Get2FAByID retrieves a 2FA record by ID
func (r *FileTwoFARepository) Get2FAByID(ctx context.Context, params Get2FAByIDParams) (TwoFAEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	twofa, exists := r.twofas[params.ID]
	if !exists {
		return TwoFAEntity{}, fmt.Errorf("2FA record not found: %s", params.ID)
	}

	// Verify login ID and type match
	if twofa.LoginID != params.LoginID {
		return TwoFAEntity{}, fmt.Errorf("2FA record not found: login ID mismatch")
	}

	if twofa.TypeValid && twofa.TwoFactorType != params.TwoFactorType {
		return TwoFAEntity{}, fmt.Errorf("2FA record not found: type mismatch")
	}

	return twofa, nil
}

// Get2FAByLoginID retrieves a 2FA record by login ID and type
func (r *FileTwoFARepository) Get2FAByLoginID(ctx context.Context, params Get2FAByLoginIDParams) (TwoFAEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, twofa := range r.twofas {
		if twofa.LoginID == params.LoginID &&
		   twofa.TypeValid &&
		   twofa.TwoFactorType == params.TwoFactorType {
			return twofa, nil
		}
	}

	return TwoFAEntity{}, fmt.Errorf("2FA record not found for login %s and type %s", params.LoginID, params.TwoFactorType)
}

// FindTwoFAsByLoginID retrieves all 2FA records for a login
func (r *FileTwoFARepository) FindTwoFAsByLoginID(ctx context.Context, loginID uuid.UUID) ([]TwoFAEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var twofas []TwoFAEntity
	for _, twofa := range r.twofas {
		if twofa.LoginID == loginID {
			twofas = append(twofas, twofa)
		}
	}

	return twofas, nil
}

// FindEnabledTwoFAs retrieves all enabled 2FA records for a login
func (r *FileTwoFARepository) FindEnabledTwoFAs(ctx context.Context, loginID uuid.UUID) ([]TwoFAEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var twofas []TwoFAEntity
	for _, twofa := range r.twofas {
		if twofa.LoginID == loginID &&
		   twofa.EnabledValid &&
		   twofa.TwoFactorEnabled {
			twofas = append(twofas, twofa)
		}
	}

	return twofas, nil
}

// load reads 2FA data from file
func (r *FileTwoFARepository) load() error {
	filePath := filepath.Join(r.dataDir, "twofa.json")

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

	var twofas []TwoFAEntity
	if err := json.Unmarshal(data, &twofas); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to map
	r.twofas = make(map[uuid.UUID]TwoFAEntity)
	for _, twofa := range twofas {
		r.twofas[twofa.ID] = twofa
	}

	return nil
}

// save writes 2FA data to file atomically
func (r *FileTwoFARepository) save() error {
	// Convert map to slice
	twofas := make([]TwoFAEntity, 0, len(r.twofas))
	for _, twofa := range r.twofas {
		twofas = append(twofas, twofa)
	}

	data, err := json.MarshalIndent(twofas, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "twofa.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "twofa.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
