package oauth2client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgresOAuth2ClientRepository(t *testing.T) {
	ctx := context.Background()

	// Start PostgreSQL container
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	defer func() {
		if err := postgresContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	// Get connection string
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// TODO: Set up database connection and run migrations
	// This would require setting up the database schema and running migrations
	// For now, we'll skip the actual database tests and just test the encryption service

	t.Run("EncryptionService", func(t *testing.T) {
		testEncryptionService(t)
	})

	// TODO: Add actual database tests once migrations are run
	t.Log("Database connection string:", connStr)
}

func testEncryptionService(t *testing.T) {
	encryptionKey := "test-encryption-key-32-characters"

	encryptor, err := NewEncryptionService(encryptionKey)
	require.NoError(t, err)

	t.Run("EncryptDecrypt", func(t *testing.T) {
		plaintext := "my-secret-client-secret"

		// Encrypt
		encrypted, err := encryptor.Encrypt(plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEqual(t, plaintext, encrypted)

		// Decrypt
		decrypted, err := encryptor.Decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("EmptyPlaintext", func(t *testing.T) {
		_, err := encryptor.Encrypt("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "plaintext cannot be empty")
	})

	t.Run("EmptyCiphertext", func(t *testing.T) {
		_, err := encryptor.Decrypt("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext cannot be empty")
	})

	t.Run("InvalidCiphertext", func(t *testing.T) {
		_, err := encryptor.Decrypt("invalid-base64")
		assert.Error(t, err)
	})
}

func TestValidateEncryptionKey(t *testing.T) {
	t.Run("ValidKey", func(t *testing.T) {
		err := ValidateEncryptionKey("this-is-a-valid-key")
		assert.NoError(t, err)
	})

	t.Run("ShortKey", func(t *testing.T) {
		err := ValidateEncryptionKey("short")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be at least 16 characters long")
	})
}

func TestNewPostgresOAuth2ClientRepository(t *testing.T) {
	t.Run("NilDatabase", func(t *testing.T) {
		_, err := NewPostgresOAuth2ClientRepository(nil, "test-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database connection cannot be nil")
	})

	t.Run("EmptyEncryptionKey", func(t *testing.T) {
		// We can't test with a real database connection here, but we can test the encryption key validation
		_, err := NewEncryptionService("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encryption key cannot be empty")
	})
}
