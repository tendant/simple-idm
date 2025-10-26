package mapper

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
func setupTestRepo(t *testing.T) (*FileMapperRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "mapper-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	repo, err := NewFileMapperRepository(tempDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

// createTestUser creates a test user entity
func createTestUser(loginID uuid.UUID, email string) UserEntity {
	return UserEntity{
		ID:             uuid.New(),
		Name:           "Test User",
		NameValid:      true,
		Email:          email,
		Phone:          "+1234567890",
		PhoneValid:     true,
		CreatedAt:      time.Now().UTC(),
		LastModifiedAt: time.Now().UTC(),
		LoginID:        loginID,
		LoginIDValid:   true,
		Groups:         []string{"admin", "users"},
		Roles:          []string{"editor", "viewer"},
	}
}

func TestFileMapperRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "mapper-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	// Should create directory if it doesn't exist
	repo, err := NewFileMapperRepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileMapperRepository_GetUsersByLoginID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()
	user1 := createTestUser(loginID, "user1@example.com")
	user2 := createTestUser(loginID, "user2@example.com")
	user3 := createTestUser(uuid.New(), "other@example.com") // Different login

	// Manually add users to repository
	repo.mutex.Lock()
	repo.users[user1.ID] = user1
	repo.users[user2.ID] = user2
	repo.users[user3.ID] = user3
	repo.mutex.Unlock()

	t.Run("WithGroups", func(t *testing.T) {
		users, err := repo.GetUsersByLoginID(ctx, loginID, true)
		require.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that groups and roles are included
		for _, user := range users {
			assert.NotEmpty(t, user.Groups)
			assert.NotEmpty(t, user.Roles)
		}
	})

	t.Run("WithoutGroups", func(t *testing.T) {
		users, err := repo.GetUsersByLoginID(ctx, loginID, false)
		require.NoError(t, err)
		assert.Len(t, users, 2)

		// Check that groups and roles are cleared
		for _, user := range users {
			assert.Nil(t, user.Groups)
			assert.Nil(t, user.Roles)
		}
	})

	t.Run("NoUsersForLogin", func(t *testing.T) {
		users, err := repo.GetUsersByLoginID(ctx, uuid.New(), true)
		require.NoError(t, err)
		assert.Empty(t, users)
	})
}

func TestFileMapperRepository_GetUserByUserID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	user := createTestUser(uuid.New(), "test@example.com")

	// Manually add user to repository
	repo.mutex.Lock()
	repo.users[user.ID] = user
	repo.mutex.Unlock()

	t.Run("WithGroups", func(t *testing.T) {
		foundUser, err := repo.GetUserByUserID(ctx, user.ID, true)
		require.NoError(t, err)
		assert.Equal(t, user.ID, foundUser.ID)
		assert.Equal(t, user.Email, foundUser.Email)
		assert.NotEmpty(t, foundUser.Groups)
		assert.NotEmpty(t, foundUser.Roles)
	})

	t.Run("WithoutGroups", func(t *testing.T) {
		foundUser, err := repo.GetUserByUserID(ctx, user.ID, false)
		require.NoError(t, err)
		assert.Equal(t, user.ID, foundUser.ID)
		assert.Nil(t, foundUser.Groups)
		assert.Nil(t, foundUser.Roles)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.GetUserByUserID(ctx, uuid.New(), true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestFileMapperRepository_FindUsernamesByEmail(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	email := "shared@example.com"
	user1 := createTestUser(uuid.New(), email)
	user1.Name = "User One"
	user2 := createTestUser(uuid.New(), email)
	user2.Name = "User Two"
	user3 := createTestUser(uuid.New(), "other@example.com")
	user3.Name = "Other User"

	// Manually add users to repository
	repo.mutex.Lock()
	repo.users[user1.ID] = user1
	repo.users[user2.ID] = user2
	repo.users[user3.ID] = user3
	repo.mutex.Unlock()

	t.Run("MultipleUsersSameEmail", func(t *testing.T) {
		usernames, err := repo.FindUsernamesByEmail(ctx, email)
		require.NoError(t, err)
		assert.Len(t, usernames, 2)
		assert.Contains(t, usernames, "User One")
		assert.Contains(t, usernames, "User Two")
	})

	t.Run("CaseInsensitiveEmail", func(t *testing.T) {
		usernames, err := repo.FindUsernamesByEmail(ctx, "SHARED@EXAMPLE.COM")
		require.NoError(t, err)
		assert.Len(t, usernames, 2)
	})

	t.Run("NoUsersWithEmail", func(t *testing.T) {
		usernames, err := repo.FindUsernamesByEmail(ctx, "nonexistent@example.com")
		require.NoError(t, err)
		assert.Empty(t, usernames)
	})

	t.Run("UserWithoutName", func(t *testing.T) {
		userNoName := createTestUser(uuid.New(), "noname@example.com")
		userNoName.Name = ""
		userNoName.NameValid = false

		repo.mutex.Lock()
		repo.users[userNoName.ID] = userNoName
		repo.mutex.Unlock()

		usernames, err := repo.FindUsernamesByEmail(ctx, "noname@example.com")
		require.NoError(t, err)
		assert.Empty(t, usernames) // Should not include users without names
	})
}

func TestFileMapperRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "mapper-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	loginID := uuid.New()
	user1 := createTestUser(loginID, "persist@example.com")

	// Create repository and add data
	repo1, err := NewFileMapperRepository(tempDir)
	require.NoError(t, err)

	repo1.mutex.Lock()
	repo1.users[user1.ID] = user1
	err = repo1.save()
	repo1.mutex.Unlock()
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileMapperRepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	foundUser, err := repo2.GetUserByUserID(ctx, user1.ID, true)
	require.NoError(t, err)
	assert.Equal(t, user1.ID, foundUser.ID)
	assert.Equal(t, user1.Email, foundUser.Email)
	assert.Equal(t, user1.Name, foundUser.Name)
	assert.Equal(t, user1.Groups, foundUser.Groups)
	assert.Equal(t, user1.Roles, foundUser.Roles)
}

func TestFileMapperRepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()
	numGoroutines := 50
	var wg sync.WaitGroup

	// Concurrent writes
	t.Run("ConcurrentWrites", func(t *testing.T) {
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				user := createTestUser(loginID, "concurrent@example.com")
				repo.mutex.Lock()
				repo.users[user.ID] = user
				repo.mutex.Unlock()
			}(i)
		}
		wg.Wait()

		// Verify all users were added
		users, err := repo.GetUsersByLoginID(ctx, loginID, true)
		require.NoError(t, err)
		assert.Equal(t, numGoroutines, len(users))
	})

	// Concurrent reads
	t.Run("ConcurrentReads", func(t *testing.T) {
		user := createTestUser(uuid.New(), "read@example.com")
		repo.mutex.Lock()
		repo.users[user.ID] = user
		repo.mutex.Unlock()

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.GetUserByUserID(ctx, user.ID, true)
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

	// Mixed concurrent reads and writes
	t.Run("MixedConcurrentAccess", func(t *testing.T) {
		testLoginID := uuid.New()
		wg.Add(numGoroutines * 2)

		// Writers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				user := createTestUser(testLoginID, "mixed@example.com")
				repo.mutex.Lock()
				repo.users[user.ID] = user
				repo.mutex.Unlock()
			}()
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.GetUsersByLoginID(ctx, testLoginID, true)
			}()
		}

		wg.Wait()

		// Verify final state
		users, err := repo.GetUsersByLoginID(ctx, testLoginID, true)
		require.NoError(t, err)
		assert.Equal(t, numGoroutines, len(users))
	})
}

func TestFileMapperRepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)

	// Add multiple users
	users := []UserEntity{
		createTestUser(uuid.New(), "user1@example.com"),
		createTestUser(uuid.New(), "user2@example.com"),
		createTestUser(uuid.New(), "user3@example.com"),
	}

	repo.mutex.Lock()
	for _, user := range users {
		repo.users[user.ID] = user
	}
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Load and verify
	repo.mutex.Lock()
	repo.users = make(map[uuid.UUID]UserEntity) // Clear
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Len(t, repo.users, 3)
	for _, user := range users {
		loaded, exists := repo.users[user.ID]
		assert.True(t, exists)
		assert.Equal(t, user.Email, loaded.Email)
	}
}

func TestFileMapperRepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository should not error
	users, err := repo.GetUsersByLoginID(ctx, uuid.New(), true)
	require.NoError(t, err)
	assert.Empty(t, users)

	usernames, err := repo.FindUsernamesByEmail(ctx, "any@example.com")
	require.NoError(t, err)
	assert.Empty(t, usernames)
}
