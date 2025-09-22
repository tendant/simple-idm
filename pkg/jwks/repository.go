package jwks

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// JWKSRepository defines the interface for JWKS key storage operations
type JWKSRepository interface {
	// Core keystore operations

	// GetKeyStore retrieves the entire key store
	GetKeyStore(ctx context.Context) (*KeyStore, error)

	// SaveKeyStore saves the entire key store
	SaveKeyStore(ctx context.Context, keyStore *KeyStore) error

	// Key-specific operations

	// GetKeyByID retrieves a key pair by its ID
	GetKeyByID(ctx context.Context, kid string) (*KeyPair, error)

	// GetActiveKey retrieves the currently active signing key
	GetActiveKey(ctx context.Context) (*KeyPair, error)

	// AddKey adds a new key pair to the store
	AddKey(ctx context.Context, keyPair *KeyPair) error

	// UpdateKey updates an existing key pair
	UpdateKey(ctx context.Context, keyPair *KeyPair) error

	// DeleteKey removes a key pair by its ID
	DeleteKey(ctx context.Context, kid string) error

	// SetActiveKey sets a key as active and deactivates others
	SetActiveKey(ctx context.Context, kid string) error

	// Query operations

	// ListKeys returns all key pairs
	ListKeys(ctx context.Context) ([]*KeyPair, error)

	// GetKeysByStatus returns keys filtered by active status
	GetKeysByStatus(ctx context.Context, active bool) ([]*KeyPair, error)

	// GetKeysOlderThan returns keys created before the specified time
	GetKeysOlderThan(ctx context.Context, cutoffTime time.Time) ([]*KeyPair, error)

	// Administrative operations

	// GetKeyCount returns the total number of keys
	GetKeyCount(ctx context.Context) (int64, error)

	// CleanupOldKeys removes keys older than the specified duration, preserving active keys
	CleanupOldKeys(ctx context.Context, maxAge time.Duration) error

	// KeyExists checks if a key with the given ID exists
	KeyExists(ctx context.Context, kid string) (bool, error)

	// Transaction support for future database implementations

	// WithTx returns a new repository instance that uses the provided transaction
	WithTx(tx interface{}) JWKSRepository
}

// KeyPairEntity represents additional metadata that might be stored with key pairs
// This can be extended when moving to database storage
type KeyPairEntity struct {
	*KeyPair
	UpdatedAt   time.Time
	LastUsedAt  *time.Time // Last time this key was used for signing
	Description string     // Optional description of the key
	Version     int        // Version number for optimistic locking
}

// CreateKeyParams represents parameters for creating a new key pair
type CreateKeyParams struct {
	Kid         string
	Alg         string
	KeySize     int    // RSA key size in bits
	Active      bool   // Whether this should be the active key
	Description string // Optional description
}

// UpdateKeyParams represents parameters for updating a key pair
type UpdateKeyParams struct {
	Kid         string
	Active      *bool   // Pointer to allow nil (no update)
	Description *string // Pointer to allow nil (no update)
}

// ListKeysParams represents parameters for listing keys with filtering
type ListKeysParams struct {
	Active        *bool      // Filter by active status
	Algorithm     *string    // Filter by algorithm
	CreatedAfter  *time.Time // Filter by creation time
	CreatedBefore *time.Time // Filter by creation time
}

// InMemoryJWKSRepository implements JWKSRepository using in-memory storage
type InMemoryJWKSRepository struct {
	keyStore *KeyStore
	mutex    sync.RWMutex
}

// NewInMemoryJWKSRepository creates a new in-memory JWKS repository
func NewInMemoryJWKSRepository() *InMemoryJWKSRepository {
	return &InMemoryJWKSRepository{
		keyStore: &KeyStore{Keys: []KeyPair{}},
	}
}

// GetKeyStore retrieves the entire key store
func (r *InMemoryJWKSRepository) GetKeyStore(ctx context.Context) (*KeyStore, error) {
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
func (r *InMemoryJWKSRepository) SaveKeyStore(ctx context.Context, keyStore *KeyStore) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Deep copy to prevent external modifications
	r.keyStore = &KeyStore{
		Keys: make([]KeyPair, len(keyStore.Keys)),
	}
	copy(r.keyStore.Keys, keyStore.Keys)

	return nil
}

// GetKeyByID retrieves a key pair by its ID
func (r *InMemoryJWKSRepository) GetKeyByID(ctx context.Context, kid string) (*KeyPair, error) {
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
func (r *InMemoryJWKSRepository) GetActiveKey(ctx context.Context) (*KeyPair, error) {
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
func (r *InMemoryJWKSRepository) AddKey(ctx context.Context, keyPair *KeyPair) error {
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
	return nil
}

// UpdateKey updates an existing key pair
func (r *InMemoryJWKSRepository) UpdateKey(ctx context.Context, keyPair *KeyPair) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, existingKey := range r.keyStore.Keys {
		if existingKey.Kid == keyPair.Kid {
			r.keyStore.Keys[i] = *keyPair
			return nil
		}
	}

	return fmt.Errorf("key not found: %s", keyPair.Kid)
}

// DeleteKey removes a key pair by its ID
func (r *InMemoryJWKSRepository) DeleteKey(ctx context.Context, kid string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, keyPair := range r.keyStore.Keys {
		if keyPair.Kid == kid {
			// Remove the key by slicing
			r.keyStore.Keys = append(r.keyStore.Keys[:i], r.keyStore.Keys[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("key not found: %s", kid)
}

// SetActiveKey sets a key as active and deactivates others
func (r *InMemoryJWKSRepository) SetActiveKey(ctx context.Context, kid string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	keyFound := false
	for i := range r.keyStore.Keys {
		if r.keyStore.Keys[i].Kid == kid {
			r.keyStore.Keys[i].Active = true
			keyFound = true
		} else {
			r.keyStore.Keys[i].Active = false
		}
	}

	if !keyFound {
		return fmt.Errorf("key not found: %s", kid)
	}

	return nil
}

// ListKeys returns all key pairs
func (r *InMemoryJWKSRepository) ListKeys(ctx context.Context) ([]*KeyPair, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	keys := make([]*KeyPair, len(r.keyStore.Keys))
	for i, keyPair := range r.keyStore.Keys {
		keyCopy := keyPair
		keys[i] = &keyCopy
	}

	return keys, nil
}

// GetKeysByStatus returns keys filtered by active status
func (r *InMemoryJWKSRepository) GetKeysByStatus(ctx context.Context, active bool) ([]*KeyPair, error) {
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
func (r *InMemoryJWKSRepository) GetKeysOlderThan(ctx context.Context, cutoffTime time.Time) ([]*KeyPair, error) {
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
func (r *InMemoryJWKSRepository) GetKeyCount(ctx context.Context) (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return int64(len(r.keyStore.Keys)), nil
}

// CleanupOldKeys removes keys older than the specified duration, preserving active keys
func (r *InMemoryJWKSRepository) CleanupOldKeys(ctx context.Context, maxAge time.Duration) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	cutoffTime := time.Now().Add(-maxAge).UTC()
	var keysToKeep []KeyPair

	for _, keyPair := range r.keyStore.Keys {
		// Always keep the active key, regardless of age
		if keyPair.Active || keyPair.CreatedAt.After(cutoffTime) {
			keysToKeep = append(keysToKeep, keyPair)
		}
	}

	r.keyStore.Keys = keysToKeep
	return nil
}

// KeyExists checks if a key with the given ID exists
func (r *InMemoryJWKSRepository) KeyExists(ctx context.Context, kid string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, keyPair := range r.keyStore.Keys {
		if keyPair.Kid == kid {
			return true, nil
		}
	}

	return false, nil
}

// WithTx returns a new repository instance that uses the provided transaction
// For in-memory implementation, this returns the same instance since there are no transactions
func (r *InMemoryJWKSRepository) WithTx(tx interface{}) JWKSRepository {
	// For in-memory implementation, we don't support transactions
	// Return the same instance
	return r
}
