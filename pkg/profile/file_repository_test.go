package profile

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
func setupTestRepo(t *testing.T) (*FileProfileRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "profile-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	repo, err := NewFileProfileRepository(tempDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

// createTestProfile creates a test profile
func createTestProfile(id uuid.UUID, loginID uuid.UUID, username, email string) Profile {
	return Profile{
		ID:             id,
		Email:          email,
		CreatedAt:      time.Now().UTC(),
		LastModifiedAt: time.Now().UTC(),
		LoginID:        loginID,
		Username:       username,
	}
}

// createTestLogin creates a test login record
func createTestLogin(id uuid.UUID, username string) LoginRecord {
	return LoginRecord{
		ID:       id,
		Username: username,
	}
}

func TestFileProfileRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "profile-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	// Should create directory if it doesn't exist
	repo, err := NewFileProfileRepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileProfileRepository_GetUserById(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	loginID := uuid.New()
	profile := createTestProfile(userID, loginID, "testuser", "test@example.com")

	// Manually add profile to repository
	repo.mutex.Lock()
	repo.data.Users[userID] = profile
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		foundProfile, err := repo.GetUserById(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, profile.ID, foundProfile.ID)
		assert.Equal(t, profile.Email, foundProfile.Email)
		assert.Equal(t, profile.Username, foundProfile.Username)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.GetUserById(ctx, uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestFileProfileRepository_GetLoginById(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()
	login := createTestLogin(loginID, "testlogin")

	// Manually add login to repository
	repo.mutex.Lock()
	repo.data.Logins[loginID] = login
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		foundLogin, err := repo.GetLoginById(ctx, loginID)
		require.NoError(t, err)
		assert.Equal(t, login.ID, foundLogin.ID)
		assert.Equal(t, login.Username, foundLogin.Username)
	})

	t.Run("LoginNotFound", func(t *testing.T) {
		_, err := repo.GetLoginById(ctx, uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "login not found")
	})
}

func TestFileProfileRepository_FindUserByUsername(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	username := "testuser"
	user1 := createTestProfile(uuid.New(), uuid.New(), username, "user1@example.com")
	user2 := createTestProfile(uuid.New(), uuid.New(), username, "user2@example.com")
	user3 := createTestProfile(uuid.New(), uuid.New(), "otheruser", "other@example.com")

	// Manually add profiles to repository
	repo.mutex.Lock()
	repo.data.Users[user1.ID] = user1
	repo.data.Users[user2.ID] = user2
	repo.data.Users[user3.ID] = user3
	repo.mutex.Unlock()

	t.Run("MultipleUsersWithSameUsername", func(t *testing.T) {
		users, err := repo.FindUserByUsername(ctx, username)
		require.NoError(t, err)
		assert.Len(t, users, 2)
	})

	t.Run("CaseInsensitiveSearch", func(t *testing.T) {
		users, err := repo.FindUserByUsername(ctx, "TESTUSER")
		require.NoError(t, err)
		assert.Len(t, users, 2)
	})

	t.Run("NoResults", func(t *testing.T) {
		users, err := repo.FindUserByUsername(ctx, "nonexistent")
		require.NoError(t, err)
		assert.Empty(t, users)
	})
}

func TestFileProfileRepository_UpdateUsername(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	profile := createTestProfile(userID, uuid.New(), "oldusername", "test@example.com")

	// Manually add profile to repository
	repo.mutex.Lock()
	repo.data.Users[userID] = profile
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		err := repo.UpdateUsername(ctx, UpdateUsernameParam{
			ID:       userID,
			Username: "newusername",
		})
		require.NoError(t, err)

		// Verify username was updated
		updatedProfile, err := repo.GetUserById(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, "newusername", updatedProfile.Username)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		err := repo.UpdateUsername(ctx, UpdateUsernameParam{
			ID:       uuid.New(),
			Username: "whatever",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestFileProfileRepository_UpdateLoginId(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	oldLoginID := uuid.New()
	newLoginID := uuid.New()

	profile := createTestProfile(userID, oldLoginID, "testuser", "test@example.com")

	// Manually add profile to repository
	repo.mutex.Lock()
	repo.data.Users[userID] = profile
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		returnedLoginID, err := repo.UpdateLoginId(ctx, UpdateLoginIdParam{
			ID:      userID,
			LoginID: uuid.NullUUID{UUID: newLoginID, Valid: true},
		})
		require.NoError(t, err)
		assert.Equal(t, newLoginID, returnedLoginID)

		// Verify login ID was updated
		updatedProfile, err := repo.GetUserById(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, newLoginID, updatedProfile.LoginID)
	})

	t.Run("SetToNull", func(t *testing.T) {
		returnedLoginID, err := repo.UpdateLoginId(ctx, UpdateLoginIdParam{
			ID:      userID,
			LoginID: uuid.NullUUID{Valid: false},
		})
		require.NoError(t, err)
		assert.Equal(t, uuid.Nil, returnedLoginID)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.UpdateLoginId(ctx, UpdateLoginIdParam{
			ID:      uuid.New(),
			LoginID: uuid.NullUUID{UUID: newLoginID, Valid: true},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestFileProfileRepository_GetUserPhone(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	phone := "+1234567890"

	// Manually add phone to repository
	repo.mutex.Lock()
	repo.data.Phones[userID] = phone
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		foundPhone, err := repo.GetUserPhone(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, phone, foundPhone)
	})

	t.Run("NoPhoneSet", func(t *testing.T) {
		foundPhone, err := repo.GetUserPhone(ctx, uuid.New())
		require.NoError(t, err)
		assert.Empty(t, foundPhone)
	})
}

func TestFileProfileRepository_UpdateUserPhone(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	profile := createTestProfile(userID, uuid.New(), "testuser", "test@example.com")

	// Manually add profile to repository
	repo.mutex.Lock()
	repo.data.Users[userID] = profile
	repo.mutex.Unlock()

	t.Run("SetPhone", func(t *testing.T) {
		newPhone := "+1987654321"
		err := repo.UpdateUserPhone(ctx, UpdatePhoneParams{
			ID:    userID,
			Phone: newPhone,
		})
		require.NoError(t, err)

		// Verify phone was set
		phone, err := repo.GetUserPhone(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, newPhone, phone)
	})

	t.Run("ClearPhone", func(t *testing.T) {
		err := repo.UpdateUserPhone(ctx, UpdatePhoneParams{
			ID:    userID,
			Phone: "",
		})
		require.NoError(t, err)

		// Verify phone was cleared
		phone, err := repo.GetUserPhone(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, phone)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		err := repo.UpdateUserPhone(ctx, UpdatePhoneParams{
			ID:    uuid.New(),
			Phone: "+1234567890",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestFileProfileRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "profile-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	userID := uuid.New()
	loginID := uuid.New()
	profile := createTestProfile(userID, loginID, "persistuser", "persist@example.com")

	login := createTestLogin(loginID, "persistlogin")
	phone := "+1234567890"

	// Create repository and add data
	repo1, err := NewFileProfileRepository(tempDir)
	require.NoError(t, err)

	repo1.mutex.Lock()
	repo1.data.Users[userID] = profile
	repo1.data.Logins[loginID] = login
	repo1.data.Phones[userID] = phone
	err = repo1.save()
	repo1.mutex.Unlock()
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileProfileRepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	foundProfile, err := repo2.GetUserById(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, foundProfile.ID)
	assert.Equal(t, profile.Username, foundProfile.Username)

	foundLogin, err := repo2.GetLoginById(ctx, loginID)
	require.NoError(t, err)
	assert.Equal(t, login.ID, foundLogin.ID)

	foundPhone, err := repo2.GetUserPhone(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, phone, foundPhone)
}

func TestFileProfileRepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentWrites", func(t *testing.T) {
		// Create initial profiles
		profiles := make(map[uuid.UUID]Profile)
		for i := 0; i < numGoroutines; i++ {
			userID := uuid.New()
			profile := createTestProfile(userID, uuid.New(), "user", "user@example.com")
			profiles[userID] = profile
			repo.mutex.Lock()
			repo.data.Users[userID] = profile
			repo.mutex.Unlock()
		}

		// Concurrent username updates
		wg.Add(numGoroutines)
		for userID := range profiles {
			go func(id uuid.UUID) {
				defer wg.Done()
				_ = repo.UpdateUsername(ctx, UpdateUsernameParam{
					ID:       id,
					Username: "updated",
				})
			}(userID)
		}
		wg.Wait()

		// Verify all were updated
		for userID := range profiles {
			profile, err := repo.GetUserById(ctx, userID)
			require.NoError(t, err)
			assert.Equal(t, "updated", profile.Username)
		}
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		userID := uuid.New()
		profile := createTestProfile(userID, uuid.New(), "readuser", "read@example.com")

		repo.mutex.Lock()
		repo.data.Users[userID] = profile
		repo.mutex.Unlock()

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.GetUserById(ctx, userID)
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
		testUserID := uuid.New()
		testProfile := createTestProfile(testUserID, uuid.New(), "mixed", "mixed@example.com")

		repo.mutex.Lock()
		repo.data.Users[testUserID] = testProfile
		repo.mutex.Unlock()

		wg.Add(numGoroutines * 2)

		// Writers (username updates)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_ = repo.UpdateUsername(ctx, UpdateUsernameParam{
					ID:       testUserID,
					Username: "concurrent",
				})
			}()
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.GetUserById(ctx, testUserID)
			}()
		}

		wg.Wait()

		// Verify final state
		profile, err := repo.GetUserById(ctx, testUserID)
		require.NoError(t, err)
		assert.Equal(t, "concurrent", profile.Username)
	})
}

func TestFileProfileRepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)

	// Add multiple profiles, logins, and phones
	for i := 0; i < 3; i++ {
		userID := uuid.New()
		loginID := uuid.New()

		profile := createTestProfile(userID, loginID, "user", "user@example.com")
		login := createTestLogin(loginID, "login")
		phone := "+1234567890"

		repo.mutex.Lock()
		repo.data.Users[userID] = profile
		repo.data.Logins[loginID] = login
		repo.data.Phones[userID] = phone
		repo.mutex.Unlock()
	}

	initialUserCount := len(repo.data.Users)
	initialLoginCount := len(repo.data.Logins)
	initialPhoneCount := len(repo.data.Phones)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.data = &fileProfileData{
		Users:  make(map[uuid.UUID]Profile),
		Logins: make(map[uuid.UUID]LoginRecord),
		Phones: make(map[uuid.UUID]string),
	}
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialUserCount, len(repo.data.Users))
	assert.Equal(t, initialLoginCount, len(repo.data.Logins))
	assert.Equal(t, initialPhoneCount, len(repo.data.Phones))
}

func TestFileProfileRepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository operations should return appropriate errors/empty results
	_, err := repo.GetUserById(ctx, uuid.New())
	assert.Error(t, err)

	_, err = repo.GetLoginById(ctx, uuid.New())
	assert.Error(t, err)

	users, err := repo.FindUserByUsername(ctx, "anyone")
	require.NoError(t, err)
	assert.Empty(t, users)

	phone, err := repo.GetUserPhone(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, phone)
}
