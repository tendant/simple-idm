package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileJWKSRepository implements JWKSRepository using file-based storage
type FileJWKSRepository struct {
	dataDir  string
	keyStore *KeyStore
	mutex    sync.RWMutex
}

// NewFileJWKSRepository creates a new file-based JWKS repository
func NewFileJWKSRepository(dataDir string) (*FileJWKSRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileJWKSRepository{
		dataDir:  dataDir,
		keyStore: &KeyStore{Keys: []KeyPair{}},
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// GetKeyStore retrieves the entire key store
func (r *FileJWKSRepository) GetKeyStore(ctx context.Context) (*KeyStore, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Deep copy the keystore to prevent external modifications
	keyStore := &KeyStore{
		Keys: make([]KeyPair, len(r.keyStore.Keys)),
	}
	copy(keyStore.Keys, r.keyStore.Keys)

	return keyStore, nil
}

// SaveKeyStore saves the entire key store
func (r *FileJWKSRepository) SaveKeyStore(ctx context.Context, keyStore *KeyStore) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Deep copy to prevent external modifications
	r.keyStore = &KeyStore{
		Keys: make([]KeyPair, len(keyStore.Keys)),
	}
	copy(r.keyStore.Keys, keyStore.Keys)

	// Persist to file
	return r.save()
}

// GetKeyByID retrieves a key pair by its ID
func (r *FileJWKSRepository) GetKeyByID(ctx context.Context, kid string) (*KeyPair, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, keyPair := range r.keyStore.Keys {
		if keyPair.Kid == kid {
			// Return a copy to prevent external modifications
			keyCopy := keyPair
			return &keyCopy, nil
		}
	}

	return nil, fmt.Errorf("key not found: %s", kid)
}

// GetActiveKey retrieves the currently active signing key
func (r *FileJWKSRepository) GetActiveKey(ctx context.Context) (*KeyPair, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, keyPair := range r.keyStore.Keys {
		if keyPair.Active {
			// Return a copy to prevent external modifications
			keyCopy := keyPair
			return &keyCopy, nil
		}
	}

	return nil, fmt.Errorf("no active key found")
}

// AddKey adds a new key pair to the store
func (r *FileJWKSRepository) AddKey(ctx context.Context, keyPair *KeyPair) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if key already exists
	for _, existingKey := range r.keyStore.Keys {
		if existingKey.Kid == keyPair.Kid {
			return fmt.Errorf("key already exists: %s", keyPair.Kid)
		}
	}

	// Add the key
	r.keyStore.Keys = append(r.keyStore.Keys, *keyPair)

	// Persist to file
	return r.save()
}

// UpdateKey updates an existing key pair
func (r *FileJWKSRepository) UpdateKey(ctx context.Context, keyPair *KeyPair) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, existingKey := range r.keyStore.Keys {
		if existingKey.Kid == keyPair.Kid {
			r.keyStore.Keys[i] = *keyPair

			// Persist to file
			return r.save()
		}
	}

	return fmt.Errorf("key not found: %s", keyPair.Kid)
}

// DeleteKey removes a key pair by its ID
func (r *FileJWKSRepository) DeleteKey(ctx context.Context, kid string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, existingKey := range r.keyStore.Keys {
		if existingKey.Kid == kid {
			// Remove the key by slicing
			r.keyStore.Keys = append(r.keyStore.Keys[:i], r.keyStore.Keys[i+1:]...)

			// Persist to file
			return r.save()
		}
	}

	return fmt.Errorf("key not found: %s", kid)
}

// SetActiveKey sets a key as active and deactivates others
func (r *FileJWKSRepository) SetActiveKey(ctx context.Context, kid string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	found := false
	for i := range r.keyStore.Keys {
		if r.keyStore.Keys[i].Kid == kid {
			r.keyStore.Keys[i].Active = true
			found = true
		} else {
			r.keyStore.Keys[i].Active = false
		}
	}

	if !found {
		return fmt.Errorf("key not found: %s", kid)
	}

	// Persist to file
	return r.save()
}

// ListKeys returns all key pairs
func (r *FileJWKSRepository) ListKeys(ctx context.Context) ([]*KeyPair, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	keys := make([]*KeyPair, len(r.keyStore.Keys))
	for i := range r.keyStore.Keys {
		keyCopy := r.keyStore.Keys[i]
		keys[i] = &keyCopy
	}

	return keys, nil
}

// GetKeysByStatus returns keys filtered by active status
func (r *FileJWKSRepository) GetKeysByStatus(ctx context.Context, active bool) ([]*KeyPair, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var keys []*KeyPair
	for _, keyPair := range r.keyStore.Keys {
		if keyPair.Active == active {
			keyCopy := keyPair
			keys = append(keys, &keyCopy)
		}
	}

	return keys, nil
}

// GetKeysOlderThan returns keys created before the specified time
func (r *FileJWKSRepository) GetKeysOlderThan(ctx context.Context, cutoffTime time.Time) ([]*KeyPair, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var keys []*KeyPair
	for _, keyPair := range r.keyStore.Keys {
		if keyPair.CreatedAt.Before(cutoffTime) {
			keyCopy := keyPair
			keys = append(keys, &keyCopy)
		}
	}

	return keys, nil
}

// GetKeyCount returns the total number of keys
func (r *FileJWKSRepository) GetKeyCount(ctx context.Context) (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return int64(len(r.keyStore.Keys)), nil
}

// CleanupOldKeys removes keys older than the specified duration, preserving active keys
func (r *FileJWKSRepository) CleanupOldKeys(ctx context.Context, maxAge time.Duration) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	cutoffTime := time.Now().Add(-maxAge)
	newKeys := []KeyPair{}

	for _, keyPair := range r.keyStore.Keys {
		// Keep active keys or keys within the age limit
		if keyPair.Active || keyPair.CreatedAt.After(cutoffTime) {
			newKeys = append(newKeys, keyPair)
		}
	}

	r.keyStore.Keys = newKeys

	// Persist to file
	return r.save()
}

// KeyExists checks if a key with the given ID exists
func (r *FileJWKSRepository) KeyExists(ctx context.Context, kid string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, keyPair := range r.keyStore.Keys {
		if keyPair.Kid == kid {
			return true, nil
		}
	}

	return false, nil
}

// WithTx returns a new repository with the given transaction
// File-based implementation doesn't support transactions, returns self
func (r *FileJWKSRepository) WithTx(tx interface{}) JWKSRepository {
	// File-based storage doesn't support transactions
	// Return self to maintain interface compatibility
	return r
}

// load reads JWKS data from file
func (r *FileJWKSRepository) load() error {
	filePath := filepath.Join(r.dataDir, "jwks.json")

	// If file doesn't exist, start with empty keystore
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty keystore
	if len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, r.keyStore); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// save writes JWKS data to file atomically
func (r *FileJWKSRepository) save() error {
	data, err := json.MarshalIndent(r.keyStore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "jwks.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "jwks.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
