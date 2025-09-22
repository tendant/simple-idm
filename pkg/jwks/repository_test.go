package jwks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryJWKSRepository(t *testing.T) {
	ctx := context.Background()

	t.Run("NewInMemoryJWKSRepository", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()
		assert.NotNil(t, repo)
		assert.NotNil(t, repo.keyStore)
		assert.Empty(t, repo.keyStore.Keys)
	})

	t.Run("GetKeyStore_Empty", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()
		keyStore, err := repo.GetKeyStore(ctx)
		require.NoError(t, err)
		assert.NotNil(t, keyStore)
		assert.Empty(t, keyStore.Keys)
	})

	t.Run("AddKey_Success", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Generate a test key pair
		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "test-key-1",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Verify key was added
		keyStore, err := repo.GetKeyStore(ctx)
		require.NoError(t, err)
		assert.Len(t, keyStore.Keys, 1)
		assert.Equal(t, "test-key-1", keyStore.Keys[0].Kid)
	})

	t.Run("AddKey_Duplicate", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "test-key-1",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		// Add key first time
		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Try to add same key again
		err = repo.AddKey(ctx, keyPair)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key already exists")
	})

	t.Run("GetKeyByID_Success", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "test-key-1",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Get key by ID
		retrievedKey, err := repo.GetKeyByID(ctx, "test-key-1")
		require.NoError(t, err)
		assert.Equal(t, "test-key-1", retrievedKey.Kid)
		assert.Equal(t, "RS256", retrievedKey.Alg)
		assert.True(t, retrievedKey.Active)
	})

	t.Run("GetKeyByID_NotFound", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		_, err := repo.GetKeyByID(ctx, "non-existent-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})

	t.Run("GetActiveKey_Success", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "active-key",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Get active key
		activeKey, err := repo.GetActiveKey(ctx)
		require.NoError(t, err)
		assert.Equal(t, "active-key", activeKey.Kid)
		assert.True(t, activeKey.Active)
	})

	t.Run("GetActiveKey_NotFound", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		_, err := repo.GetActiveKey(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active key found")
	})

	t.Run("SetActiveKey_Success", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Add two keys
		privateKey1, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)
		privateKey2, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair1 := &KeyPair{
			Kid:        "key-1",
			Alg:        "RS256",
			PrivateKey: privateKey1,
			PublicKey:  &privateKey1.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		keyPair2 := &KeyPair{
			Kid:        "key-2",
			Alg:        "RS256",
			PrivateKey: privateKey2,
			PublicKey:  &privateKey2.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     false,
		}

		err = repo.AddKey(ctx, keyPair1)
		require.NoError(t, err)
		err = repo.AddKey(ctx, keyPair2)
		require.NoError(t, err)

		// Set key-2 as active
		err = repo.SetActiveKey(ctx, "key-2")
		require.NoError(t, err)

		// Verify key-2 is now active and key-1 is not
		key1, err := repo.GetKeyByID(ctx, "key-1")
		require.NoError(t, err)
		assert.False(t, key1.Active)

		key2, err := repo.GetKeyByID(ctx, "key-2")
		require.NoError(t, err)
		assert.True(t, key2.Active)

		// Verify GetActiveKey returns key-2
		activeKey, err := repo.GetActiveKey(ctx)
		require.NoError(t, err)
		assert.Equal(t, "key-2", activeKey.Kid)
	})

	t.Run("SetActiveKey_NotFound", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		err := repo.SetActiveKey(ctx, "non-existent-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})

	t.Run("UpdateKey_Success", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "test-key",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     false,
		}

		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Update the key to be active
		keyPair.Active = true
		err = repo.UpdateKey(ctx, keyPair)
		require.NoError(t, err)

		// Verify update
		updatedKey, err := repo.GetKeyByID(ctx, "test-key")
		require.NoError(t, err)
		assert.True(t, updatedKey.Active)
	})

	t.Run("DeleteKey_Success", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "test-key",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Delete the key
		err = repo.DeleteKey(ctx, "test-key")
		require.NoError(t, err)

		// Verify key is deleted
		_, err = repo.GetKeyByID(ctx, "test-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})

	t.Run("ListKeys", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Add multiple keys
		for i := 0; i < 3; i++ {
			privateKey, err := GenerateRSAKeyPair(2048)
			require.NoError(t, err)

			keyPair := &KeyPair{
				Kid:        fmt.Sprintf("key-%d", i),
				Alg:        "RS256",
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
				CreatedAt:  time.Now().UTC(),
				Active:     i == 0, // First key is active
			}

			err = repo.AddKey(ctx, keyPair)
			require.NoError(t, err)
		}

		// List all keys
		keys, err := repo.ListKeys(ctx)
		require.NoError(t, err)
		assert.Len(t, keys, 3)

		// Verify keys are returned as copies (not references)
		keys[0].Active = false
		activeKey, err := repo.GetActiveKey(ctx)
		require.NoError(t, err)
		assert.True(t, activeKey.Active) // Should still be true
	})

	t.Run("GetKeysByStatus", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Add keys with different statuses
		for i := 0; i < 3; i++ {
			privateKey, err := GenerateRSAKeyPair(2048)
			require.NoError(t, err)

			keyPair := &KeyPair{
				Kid:        fmt.Sprintf("key-%d", i),
				Alg:        "RS256",
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
				CreatedAt:  time.Now().UTC(),
				Active:     i == 0, // Only first key is active
			}

			err = repo.AddKey(ctx, keyPair)
			require.NoError(t, err)
		}

		// Get active keys
		activeKeys, err := repo.GetKeysByStatus(ctx, true)
		require.NoError(t, err)
		assert.Len(t, activeKeys, 1)
		assert.Equal(t, "key-0", activeKeys[0].Kid)

		// Get inactive keys
		inactiveKeys, err := repo.GetKeysByStatus(ctx, false)
		require.NoError(t, err)
		assert.Len(t, inactiveKeys, 2)
	})

	t.Run("GetKeysOlderThan", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		now := time.Now()

		// Add keys with different creation times
		for i := 0; i < 3; i++ {
			privateKey, err := GenerateRSAKeyPair(2048)
			require.NoError(t, err)

			keyPair := &KeyPair{
				Kid:        fmt.Sprintf("key-%d", i),
				Alg:        "RS256",
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
				CreatedAt:  now.Add(-time.Duration(i) * time.Hour).UTC(),
				Active:     i == 0,
			}

			err = repo.AddKey(ctx, keyPair)
			require.NoError(t, err)
		}

		// Get keys older than 30 minutes
		cutoffTime := now.Add(-30 * time.Minute)
		oldKeys, err := repo.GetKeysOlderThan(ctx, cutoffTime)
		require.NoError(t, err)
		assert.Len(t, oldKeys, 2) // key-1 and key-2 should be older
	})

	t.Run("CleanupOldKeys", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		now := time.Now()

		// Add keys with different ages
		for i := 0; i < 3; i++ {
			privateKey, err := GenerateRSAKeyPair(2048)
			require.NoError(t, err)

			keyPair := &KeyPair{
				Kid:        fmt.Sprintf("key-%d", i),
				Alg:        "RS256",
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
				CreatedAt:  now.Add(-time.Duration(i) * time.Hour).UTC(),
				Active:     i == 2, // Last (oldest) key is active
			}

			err = repo.AddKey(ctx, keyPair)
			require.NoError(t, err)
		}

		// Cleanup keys older than 30 minutes
		err := repo.CleanupOldKeys(ctx, 30*time.Minute)
		require.NoError(t, err)

		// Should keep key-0 (recent) and key-2 (active, even though old)
		keys, err := repo.ListKeys(ctx)
		require.NoError(t, err)
		assert.Len(t, keys, 2)

		// Verify active key is preserved
		activeKey, err := repo.GetActiveKey(ctx)
		require.NoError(t, err)
		assert.Equal(t, "key-2", activeKey.Kid)
	})

	t.Run("GetKeyCount", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Initially empty
		count, err := repo.GetKeyCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)

		// Add keys
		for i := 0; i < 3; i++ {
			privateKey, err := GenerateRSAKeyPair(2048)
			require.NoError(t, err)

			keyPair := &KeyPair{
				Kid:        fmt.Sprintf("key-%d", i),
				Alg:        "RS256",
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
				CreatedAt:  time.Now().UTC(),
				Active:     i == 0,
			}

			err = repo.AddKey(ctx, keyPair)
			require.NoError(t, err)
		}

		count, err = repo.GetKeyCount(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
	})

	t.Run("KeyExists", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// Key doesn't exist initially
		exists, err := repo.KeyExists(ctx, "test-key")
		require.NoError(t, err)
		assert.False(t, exists)

		// Add key
		privateKey, err := GenerateRSAKeyPair(2048)
		require.NoError(t, err)

		keyPair := &KeyPair{
			Kid:        "test-key",
			Alg:        "RS256",
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  time.Now().UTC(),
			Active:     true,
		}

		err = repo.AddKey(ctx, keyPair)
		require.NoError(t, err)

		// Key should exist now
		exists, err = repo.KeyExists(ctx, "test-key")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("WithTx", func(t *testing.T) {
		repo := NewInMemoryJWKSRepository()

		// For in-memory implementation, WithTx should return the same instance
		txRepo := repo.WithTx(nil)
		assert.Equal(t, repo, txRepo)
	})
}
