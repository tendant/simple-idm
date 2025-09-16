package jwks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSService(t *testing.T) {
	t.Run("NewJWKSServiceWithInMemoryStorage", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.NotNil(t, service.repository)
		assert.NotEmpty(t, service.activeKeyID) // Should have generated initial key
	})

	t.Run("NewJWKSService_WithRepository", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()
		service, err := NewJWKSService(repo)
		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.Equal(t, repo, service.repository)
		assert.NotEmpty(t, service.activeKeyID) // Should have generated initial key
	})

	t.Run("GetJWKS", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		jwks, err := service.GetJWKS()
		require.NoError(t, err)
		assert.NotNil(t, jwks)
		assert.Len(t, jwks.Keys, 1) // Should have initial key

		// Verify JWK structure
		jwk := jwks.Keys[0]
		assert.Equal(t, "RSA", jwk.Kty)
		assert.Equal(t, "sig", jwk.Use)
		assert.Equal(t, "RS256", jwk.Alg)
		assert.NotEmpty(t, jwk.Kid)
		assert.NotEmpty(t, jwk.N)
		assert.NotEmpty(t, jwk.E)
	})

	t.Run("GetActiveSigningKey", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		activeKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)
		assert.NotNil(t, activeKey)
		assert.True(t, activeKey.Active)
		assert.Equal(t, "RS256", activeKey.Alg)
		assert.NotNil(t, activeKey.PrivateKey)
		assert.NotNil(t, activeKey.PublicKey)
	})

	t.Run("GetKeyByID", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		// Get the active key ID
		activeKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)

		// Get key by ID
		retrievedKey, err := service.GetKeyByID(activeKey.Kid)
		require.NoError(t, err)
		assert.Equal(t, activeKey.Kid, retrievedKey.Kid)
		assert.Equal(t, activeKey.Alg, retrievedKey.Alg)
		assert.Equal(t, activeKey.Active, retrievedKey.Active)
	})

	t.Run("GetKeyByID_NotFound", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		_, err = service.GetKeyByID("non-existent-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})

	t.Run("GenerateNewKey", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		// Generate a new key
		newKey, err := service.GenerateNewKey()
		require.NoError(t, err)
		assert.NotNil(t, newKey)
		assert.NotEmpty(t, newKey.Kid)
		assert.Equal(t, "RS256", newKey.Alg)
		assert.False(t, newKey.Active) // New keys are not active by default
		assert.NotNil(t, newKey.PrivateKey)
		assert.NotNil(t, newKey.PublicKey)

		// Verify key was added to repository
		retrievedKey, err := service.GetKeyByID(newKey.Kid)
		require.NoError(t, err)
		assert.Equal(t, newKey.Kid, retrievedKey.Kid)
	})

	t.Run("RotateKeys", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		// Get the original active key
		originalActiveKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)

		// Rotate keys
		newActiveKey, err := service.RotateKeys()
		require.NoError(t, err)
		assert.NotNil(t, newActiveKey)
		assert.NotEqual(t, originalActiveKey.Kid, newActiveKey.Kid)

		// Verify the new key is now active
		currentActiveKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)
		assert.Equal(t, newActiveKey.Kid, currentActiveKey.Kid)

		// Verify the original key is no longer active
		originalKey, err := service.GetKeyByID(originalActiveKey.Kid)
		require.NoError(t, err)
		assert.False(t, originalKey.Active)

		// Verify service's activeKeyID is updated
		assert.Equal(t, newActiveKey.Kid, service.activeKeyID)
	})

	t.Run("CleanupOldKeys", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		// Generate additional keys to have something to clean up
		for i := 0; i < 3; i++ {
			_, err := service.GenerateNewKey()
			require.NoError(t, err)
		}

		// Get initial count
		jwks, err := service.GetJWKS()
		require.NoError(t, err)
		initialCount := len(jwks.Keys)
		assert.Equal(t, 4, initialCount) // 1 initial + 3 generated

		// Cleanup old keys (should keep all since they're recent)
		err = service.CleanupOldKeys(1 * time.Hour)
		require.NoError(t, err)

		// Verify count is the same (all keys are recent)
		jwks, err = service.GetJWKS()
		require.NoError(t, err)
		assert.Equal(t, initialCount, len(jwks.Keys))

		// Cleanup with very short duration (should keep only active key)
		err = service.CleanupOldKeys(1 * time.Nanosecond)
		require.NoError(t, err)

		// Should keep at least the active key
		jwks, err = service.GetJWKS()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(jwks.Keys), 1)

		// Verify active key still exists
		_, err = service.GetActiveSigningKey()
		require.NoError(t, err)
	})

	t.Run("Multiple_Keys_JWKS_Format", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		// Generate additional keys
		for i := 0; i < 2; i++ {
			_, err := service.GenerateNewKey()
			require.NoError(t, err)
		}

		// Get JWKS
		jwks, err := service.GetJWKS()
		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 3) // 1 initial + 2 generated

		// Verify all keys have proper JWK format
		for _, jwk := range jwks.Keys {
			assert.Equal(t, "RSA", jwk.Kty)
			assert.Equal(t, "sig", jwk.Use)
			assert.Equal(t, "RS256", jwk.Alg)
			assert.NotEmpty(t, jwk.Kid)
			assert.NotEmpty(t, jwk.N)
			assert.NotEmpty(t, jwk.E)
		}
	})

	t.Run("Service_With_Empty_Repository", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Create service with empty repository
		service, err := NewJWKSService(repo)
		require.NoError(t, err)

		// Should have generated initial key
		activeKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)
		assert.NotNil(t, activeKey)
		assert.True(t, activeKey.Active)

		// JWKS should contain the initial key
		jwks, err := service.GetJWKS()
		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 1)
	})

	t.Run("Service_With_Existing_Keys", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Add a key to the repository first
		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		existingKey := &KeyPair{
			Kid:        "existing-key",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		err = repo.AddKey(nil, existingKey)
		require.NoError(t, err)

		// Create service with repository that has existing keys
		service, err := NewJWKSService(repo)
		require.NoError(t, err)

		// Should use existing active key
		activeKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)
		assert.Equal(t, "existing-key", activeKey.Kid)
		assert.Equal(t, "existing-key", service.activeKeyID)

		// Should not generate additional keys
		jwks, err := service.GetJWKS()
		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 1)
	})
}

func TestJWKSService_Integration(t *testing.T) {
	t.Run("Full_Key_Lifecycle", func(t *testing.T) {
		service, err := NewJWKSServiceWithInMemoryStorage()
		require.NoError(t, err)

		// 1. Verify initial state
		jwks, err := service.GetJWKS()
		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 1)

		initialActiveKey, err := service.GetActiveSigningKey()
		require.NoError(t, err)

		// 2. Generate new keys
		newKey1, err := service.GenerateNewKey()
		require.NoError(t, err)
		newKey2, err := service.GenerateNewKey()
		require.NoError(t, err)

		// 3. Verify all keys are present
		jwks, err = service.GetJWKS()
		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 3)

		// 4. Rotate to new key
		rotatedKey, err := service.RotateKeys()
		require.NoError(t, err)

		// 5. Verify rotation worked
		currentActive, err := service.GetActiveSigningKey()
		require.NoError(t, err)
		assert.Equal(t, rotatedKey.Kid, currentActive.Kid)
		assert.NotEqual(t, initialActiveKey.Kid, currentActive.Kid)

		// 6. Verify old keys are inactive
		oldKey, err := service.GetKeyByID(initialActiveKey.Kid)
		require.NoError(t, err)
		assert.False(t, oldKey.Active)

		key1, err := service.GetKeyByID(newKey1.Kid)
		require.NoError(t, err)
		assert.False(t, key1.Active)

		key2, err := service.GetKeyByID(newKey2.Kid)
		require.NoError(t, err)
		assert.False(t, key2.Active)

		// 7. Cleanup old keys
		err = service.CleanupOldKeys(1 * time.Nanosecond)
		require.NoError(t, err)

		// 8. Verify active key is preserved
		finalActive, err := service.GetActiveSigningKey()
		require.NoError(t, err)
		assert.Equal(t, rotatedKey.Kid, finalActive.Kid)
	})
}
