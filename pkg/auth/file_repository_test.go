package auth

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestRepo creates a temporary directory and repository for testing
func setupTestRepo(t *testing.T) (*FileAuthRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "auth-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	repo, err := NewFileAuthRepository(tempDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

// createTestUser creates a test user auth entity
func createTestUser(userUUID uuid.UUID, username, email, password string) UserAuthEntity {
	return UserAuthEntity{
		UUID:          userUUID,
		Name:          "Test User",
		NameValid:     true,
		Username:      username,
		UsernameValid: true,
		Email:         email,
		Password:      password,
		PasswordValid: true,
	}
}

func TestFileAuthRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "auth-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	// Should create directory if it doesn't exist
	repo, err := NewFileAuthRepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileAuthRepository_FindUserByUserUUID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userUUID := uuid.New()
	user := createTestUser(userUUID, "testuser", "test@example.com", "hashed_password")

	// Manually add user to repository
	repo.mutex.Lock()
	repo.users[userUUID] = user
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		foundUser, err := repo.FindUserByUserUUID(ctx, userUUID)
		require.NoError(t, err)
		assert.Equal(t, user.UUID, foundUser.UUID)
		assert.Equal(t, user.Username, foundUser.Username)
		assert.Equal(t, user.Email, foundUser.Email)
		assert.Equal(t, user.Password, foundUser.Password)
		assert.True(t, foundUser.PasswordValid)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.FindUserByUserUUID(ctx, uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})

	t.Run("UserWithoutPassword", func(t *testing.T) {
		userNoPass := createTestUser(uuid.New(), "nopass", "nopass@example.com", "")
		userNoPass.PasswordValid = false

		repo.mutex.Lock()
		repo.users[userNoPass.UUID] = userNoPass
		repo.mutex.Unlock()

		foundUser, err := repo.FindUserByUserUUID(ctx, userNoPass.UUID)
		require.NoError(t, err)
		assert.False(t, foundUser.PasswordValid)
		assert.Empty(t, foundUser.Password)
	})
}

func TestFileAuthRepository_UpdatePassword(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userUUID := uuid.New()
	user := createTestUser(userUUID, "testuser", "test@example.com", "old_password")

	// Manually add user to repository
	repo.mutex.Lock()
	repo.users[userUUID] = user
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		newPassword := "new_hashed_password"
		params := UpdatePasswordParams{
			UserID:         userUUID,
			Password:       newPassword,
			LastModifiedAt: time.Now().UTC(),
		}

		err := repo.UpdatePassword(ctx, params)
		require.NoError(t, err)

		// Verify password was updated
		updatedUser, err := repo.FindUserByUserUUID(ctx, userUUID)
		require.NoError(t, err)
		assert.Equal(t, newPassword, updatedUser.Password)
		assert.True(t, updatedUser.PasswordValid)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		params := UpdatePasswordParams{
			UserID:         uuid.New(),
			Password:       "some_password",
			LastModifiedAt: time.Now().UTC(),
		}

		err := repo.UpdatePassword(ctx, params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestFileAuthRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "auth-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	userUUID := uuid.New()
	user := createTestUser(userUUID, "persistuser", "persist@example.com", "password123")

	// Create repository and add data
	repo1, err := NewFileAuthRepository(tempDir)
	require.NoError(t, err)

	repo1.mutex.Lock()
	repo1.users[userUUID] = user
	err = repo1.save()
	repo1.mutex.Unlock()
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileAuthRepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	foundUser, err := repo2.FindUserByUserUUID(ctx, userUUID)
	require.NoError(t, err)
	assert.Equal(t, user.UUID, foundUser.UUID)
	assert.Equal(t, user.Username, foundUser.Username)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.Password, foundUser.Password)
}

func TestFileAuthRepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentWrites", func(t *testing.T) {
		// Add initial users
		users := make(map[uuid.UUID]UserAuthEntity)
		for i := 0; i < numGoroutines; i++ {
			userUUID := uuid.New()
			user := createTestUser(userUUID, "user"+string(rune(i)), "user@example.com", "password")
			users[userUUID] = user
			repo.mutex.Lock()
			repo.users[userUUID] = user
			repo.mutex.Unlock()
		}

		// Concurrent password updates
		wg.Add(numGoroutines)
		for userUUID := range users {
			go func(uuid uuid.UUID) {
				defer wg.Done()
				params := UpdatePasswordParams{
					UserID:         uuid,
					Password:       "new_password",
					LastModifiedAt: time.Now().UTC(),
				}
				_ = repo.UpdatePassword(ctx, params)
			}(userUUID)
		}
		wg.Wait()

		// Verify all passwords were updated
		for userUUID := range users {
			user, err := repo.FindUserByUserUUID(ctx, userUUID)
			require.NoError(t, err)
			assert.Equal(t, "new_password", user.Password)
		}
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		userUUID := uuid.New()
		user := createTestUser(userUUID, "readuser", "read@example.com", "password")

		repo.mutex.Lock()
		repo.users[userUUID] = user
		repo.mutex.Unlock()

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.FindUserByUserUUID(ctx, userUUID)
				if err != nil {
					errors <- err
				}
			}()
		}
		wg.Wait()
		close(errors)

		// No errors should occur
		for err := range errors {
			t.Errorf("Concurrent read error: %v", err)
		}
	})

	t.Run("MixedConcurrentAccess", func(t *testing.T) {
		testUserUUID := uuid.New()
		testUser := createTestUser(testUserUUID, "mixeduser", "mixed@example.com", "initial")

		repo.mutex.Lock()
		repo.users[testUserUUID] = testUser
		repo.mutex.Unlock()

		wg.Add(numGoroutines * 2)

		// Writers
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				params := UpdatePasswordParams{
					UserID:         testUserUUID,
					Password:       "password" + string(rune(index)),
					LastModifiedAt: time.Now().UTC(),
				}
				_ = repo.UpdatePassword(ctx, params)
			}(i)
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.FindUserByUserUUID(ctx, testUserUUID)
			}()
		}

		wg.Wait()

		// Verify final state exists (password will be one of the updates)
		user, err := repo.FindUserByUserUUID(ctx, testUserUUID)
		require.NoError(t, err)
		assert.NotEqual(t, "initial", user.Password) // Should have been updated
	})
}

func TestFileAuthRepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)

	// Add multiple users
	users := []UserAuthEntity{
		createTestUser(uuid.New(), "user1", "user1@example.com", "pass1"),
		createTestUser(uuid.New(), "user2", "user2@example.com", "pass2"),
		createTestUser(uuid.New(), "user3", "user3@example.com", "pass3"),
	}

	repo.mutex.Lock()
	for _, user := range users {
		repo.users[user.UUID] = user
	}
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Load and verify
	repo.mutex.Lock()
	repo.users = make(map[uuid.UUID]UserAuthEntity) // Clear
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Len(t, repo.users, 3)
	for _, user := range users {
		loaded, exists := repo.users[user.UUID]
		assert.True(t, exists)
		assert.Equal(t, user.Username, loaded.Username)
		assert.Equal(t, user.Password, loaded.Password)
	}
}

func TestFileAuthRepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository should error when looking for non-existent user
	_, err := repo.FindUserByUserUUID(ctx, uuid.New())
	assert.Error(t, err)
}
