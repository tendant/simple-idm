package jwks

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// JWKSService handles JWKS operations including key generation, storage, and retrieval
type JWKSService struct {
	repository  JWKSRepository
	activeKeyID string
}

// NewJWKSService creates a new JWKS service with the provided repository
func NewJWKSService(repository JWKSRepository, keyPair *KeyPair) (*JWKSService, error) {
	service := &JWKSService{
		repository: repository,
	}

	key := &KeyPair{
		Kid:        keyPair.Kid,
		Alg:        keyPair.Alg,
		PrivateKey: keyPair.PrivateKey,
		PublicKey:  &keyPair.PrivateKey.PublicKey,
		Active:     true, // First key is active by default
	}

	ctx := context.Background()
	if err := service.repository.AddKey(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to add initial key: %w", err)
	}

	service.activeKeyID = key.Kid

	return service, nil
}

// NewJWKSServiceWithInMemoryStorage creates a new JWKS service with in-memory storage
func NewJWKSServiceWithKey(keyPair *KeyPair) (*JWKSService, error) {
	repository := NewInMemoryJWKSRepository()
	return NewJWKSService(repository, keyPair)
}

func NewJWKSServiceWithInMemoryStorage() (*JWKSService, error) {
	service := &JWKSService{
		repository: NewInMemoryJWKSRepository(),
	}
	service.generateInitialKey()
	return service, nil
}

// GetJWKS returns the public keys in JWKS format
func (s *JWKSService) GetJWKS() (*JWKS, error) {
	ctx := context.Background()
	keys, err := s.repository.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	jwks := &JWKS{
		Keys: make([]JWK, 0, len(keys)),
	}

	for _, keyPair := range keys {
		jwks.Keys = append(jwks.Keys, *keyPair.ToJWK())
	}

	return jwks, nil
}

// GetActiveSigningKey returns the currently active signing key
func (s *JWKSService) GetActiveSigningKey() (*KeyPair, error) {
	ctx := context.Background()
	activeKey, err := s.repository.GetActiveKey(ctx)
	if err != nil {
		// If no active key found, try to make the first key active
		keys, listErr := s.repository.ListKeys(ctx)
		if listErr != nil {
			return nil, fmt.Errorf("failed to list keys: %w", listErr)
		}

		if len(keys) > 0 {
			if setErr := s.repository.SetActiveKey(ctx, keys[0].Kid); setErr != nil {
				return nil, fmt.Errorf("failed to set active key: %w", setErr)
			}
			s.activeKeyID = keys[0].Kid
			return keys[0], nil
		}

		return nil, fmt.Errorf("no signing keys available")
	}

	return activeKey, nil
}

// GetKeyByID returns a key pair by its ID
func (s *JWKSService) GetKeyByID(kid string) (*KeyPair, error) {
	ctx := context.Background()
	return s.repository.GetKeyByID(ctx, kid)
}

// GenerateNewKey generates a new RSA key pair and adds it to the store
func (s *JWKSService) GenerateNewKey() (*KeyPair, error) {
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	keyPair := &KeyPair{
		Kid:        uuid.New().String(),
		Alg:        "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now().UTC(),
		Active:     false, // New keys are not active by default
	}

	ctx := context.Background()
	if err := s.repository.AddKey(ctx, keyPair); err != nil {
		return nil, fmt.Errorf("failed to add new key: %w", err)
	}

	slog.Info("Generated new RSA key pair", "kid", keyPair.Kid)
	return keyPair, nil
}

// RotateKeys generates a new key and makes it active, deactivating the old one
func (s *JWKSService) RotateKeys() (*KeyPair, error) {
	// Generate new key
	newKey, err := s.GenerateNewKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key for rotation: %w", err)
	}

	// Set the new key as active (this will deactivate others)
	ctx := context.Background()
	if err := s.repository.SetActiveKey(ctx, newKey.Kid); err != nil {
		return nil, fmt.Errorf("failed to set new key as active: %w", err)
	}

	s.activeKeyID = newKey.Kid
	slog.Info("Rotated signing keys", "new_active_kid", newKey.Kid)
	return newKey, nil
}

// generateInitialKey generates the first key pair for the service
func (s *JWKSService) generateInitialKey() error {
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		return fmt.Errorf("failed to generate initial RSA key pair: %w", err)
	}

	keyPair := &KeyPair{
		Kid:        uuid.New().String(),
		Alg:        "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now().UTC(),
		Active:     true, // First key is active by default
	}

	ctx := context.Background()
	if err := s.repository.AddKey(ctx, keyPair); err != nil {
		return fmt.Errorf("failed to add initial key: %w", err)
	}

	s.activeKeyID = keyPair.Kid
	slog.Info("Generated initial RSA key pair", "kid", keyPair.Kid)
	return nil
}

// CleanupOldKeys removes keys older than the specified duration
func (s *JWKSService) CleanupOldKeys(maxAge time.Duration) error {
	ctx := context.Background()
	return s.repository.CleanupOldKeys(ctx, maxAge)
}
