package login

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
func setupTestRepo(t *testing.T) (*FileLoginRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "login-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	repo, err := NewFileLoginRepository(tempDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

// createTestLogin creates a test login entity
func createTestLogin(username string, password []byte) LoginEntity {
	return LoginEntity{
		ID:              uuid.New(),
		Username:        username,
		UsernameValid:   true,
		Password:        password,
		PasswordVersion: 1,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
}

func TestFileLoginRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "login-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	// Should create directory if it doesn't exist
	repo, err := NewFileLoginRepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

// Test basic login CRUD operations
func TestFileLoginRepository_FindLoginByUsername(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	login := createTestLogin("testuser", []byte("hashed_password"))

	// Add login manually
	repo.mutex.Lock()
	repo.logins[login.ID] = &login
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		foundLogin, err := repo.FindLoginByUsername(ctx, "testuser", true)
		require.NoError(t, err)
		assert.Equal(t, login.ID, foundLogin.ID)
		assert.Equal(t, "testuser", foundLogin.Username)
	})

	t.Run("LoginNotFound", func(t *testing.T) {
		_, err := repo.FindLoginByUsername(ctx, "nonexistent", true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "login not found")
	})

	t.Run("InvalidUsername", func(t *testing.T) {
		_, err := repo.FindLoginByUsername(ctx, "", true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid username")
	})

	t.Run("UsernameNotValid", func(t *testing.T) {
		_, err := repo.FindLoginByUsername(ctx, "testuser", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid username")
	})
}

func TestFileLoginRepository_GetLoginById(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	login := createTestLogin("testuser", []byte("hashed_password"))

	repo.mutex.Lock()
	repo.logins[login.ID] = &login
	repo.mutex.Unlock()

	t.Run("Success", func(t *testing.T) {
		foundLogin, err := repo.GetLoginById(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, login.ID, foundLogin.ID)
	})

	t.Run("LoginNotFound", func(t *testing.T) {
		_, err := repo.GetLoginById(ctx, uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "login not found")
	})
}

// Test password management
func TestFileLoginRepository_PasswordOperations(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	login := createTestLogin("testuser", []byte("old_password"))

	repo.mutex.Lock()
	repo.logins[login.ID] = &login
	repo.mutex.Unlock()

	t.Run("GetPasswordVersion", func(t *testing.T) {
		version, valid, err := repo.GetPasswordVersion(ctx, login.ID)
		require.NoError(t, err)
		assert.True(t, valid)
		assert.Equal(t, int32(1), version)
	})

	t.Run("ResetPassword", func(t *testing.T) {
		newPassword := []byte("new_password")
		err := repo.ResetPassword(ctx, PasswordParams{
			Username: "testuser",
			Password: newPassword,
		})
		require.NoError(t, err)

		// Verify password was updated
		updatedLogin, err := repo.GetLoginById(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, newPassword, updatedLogin.Password)
	})

	t.Run("ResetPasswordById", func(t *testing.T) {
		newPassword := []byte("another_password")
		err := repo.ResetPasswordById(ctx, PasswordParams{
			ID:       login.ID,
			Password: newPassword,
		})
		require.NoError(t, err)

		updatedLogin, err := repo.GetLoginById(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, newPassword, updatedLogin.Password)
	})

	t.Run("UpdateUserPassword", func(t *testing.T) {
		newPassword := []byte("user_updated_password")
		err := repo.UpdateUserPassword(ctx, PasswordParams{
			ID:       login.ID,
			Password: newPassword,
		})
		require.NoError(t, err)

		updatedLogin, err := repo.GetLoginById(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, newPassword, updatedLogin.Password)
	})

	t.Run("UpdateUserPasswordAndVersion", func(t *testing.T) {
		newPassword := []byte("versioned_password")
		err := repo.UpdateUserPasswordAndVersion(ctx, PasswordParams{
			ID:              login.ID,
			Password:        newPassword,
			PasswordVersion: 2,
		})
		require.NoError(t, err)

		updatedLogin, err := repo.GetLoginById(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, newPassword, updatedLogin.Password)
		assert.Equal(t, int32(2), updatedLogin.PasswordVersion)
	})
}

func TestFileLoginRepository_PasswordTimestamps(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	login := createTestLogin("testuser", []byte("password"))

	repo.mutex.Lock()
	repo.logins[login.ID] = &login
	repo.mutex.Unlock()

	t.Run("GetPasswordUpdatedAt_NotSet", func(t *testing.T) {
		_, valid, err := repo.GetPasswordUpdatedAt(ctx, login.ID)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("UpdatePasswordTimestamps", func(t *testing.T) {
		updatedAt := time.Now().UTC()
		expiresAt := updatedAt.Add(90 * 24 * time.Hour)

		err := repo.UpdatePasswordTimestamps(ctx, login.ID, updatedAt, expiresAt)
		require.NoError(t, err)

		// Verify updated at
		retrievedUpdatedAt, valid, err := repo.GetPasswordUpdatedAt(ctx, login.ID)
		require.NoError(t, err)
		assert.True(t, valid)
		assert.True(t, retrievedUpdatedAt.Equal(updatedAt))

		// Verify expires at
		retrievedExpiresAt, valid, err := repo.GetPasswordExpiresAt(ctx, login.ID)
		require.NoError(t, err)
		assert.True(t, valid)
		assert.True(t, retrievedExpiresAt.Equal(expiresAt))
	})
}

// Test password reset token operations
func TestFileLoginRepository_PasswordResetToken(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()
	token := "reset_token_123"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	t.Run("InitPasswordResetToken", func(t *testing.T) {
		err := repo.InitPasswordResetToken(ctx, PasswordResetTokenParams{
			LoginID:  loginID,
			Token:    token,
			ExpireAt: expiresAt,
		})
		require.NoError(t, err)
	})

	t.Run("ValidatePasswordResetToken_Success", func(t *testing.T) {
		result, err := repo.ValidatePasswordResetToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, loginID, result.LoginID)
	})

	t.Run("ValidatePasswordResetToken_NotFound", func(t *testing.T) {
		_, err := repo.ValidatePasswordResetToken(ctx, "nonexistent_token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")
	})

	t.Run("MarkPasswordResetTokenUsed", func(t *testing.T) {
		err := repo.MarkPasswordResetTokenUsed(ctx, token)
		require.NoError(t, err)

		// Should now fail validation (token already used)
		_, err = repo.ValidatePasswordResetToken(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token already used")
	})

	t.Run("ExpirePasswordResetToken", func(t *testing.T) {
		// Create new token
		newToken := "new_token_456"
		err := repo.InitPasswordResetToken(ctx, PasswordResetTokenParams{
			LoginID:  loginID,
			Token:    newToken,
			ExpireAt: time.Now().UTC().Add(1 * time.Hour),
		})
		require.NoError(t, err)

		// Expire all tokens for this login
		err = repo.ExpirePasswordResetToken(ctx, loginID)
		require.NoError(t, err)

		// Token should now be expired
		_, err = repo.ValidatePasswordResetToken(ctx, newToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		expiredToken := "expired_token"
		err := repo.InitPasswordResetToken(ctx, PasswordResetTokenParams{
			LoginID:  loginID,
			Token:    expiredToken,
			ExpireAt: time.Now().UTC().Add(-1 * time.Hour),
		})
		require.NoError(t, err)

		_, err = repo.ValidatePasswordResetToken(ctx, expiredToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")
	})
}

// Test password history
func TestFileLoginRepository_PasswordHistory(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	t.Run("AddPasswordToHistory", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			err := repo.AddPasswordToHistory(ctx, PasswordToHistoryParams{
				LoginID:         loginID,
				PasswordHash:    []byte("password_" + string(rune(i))),
				PasswordVersion: int32(i + 1),
			})
			require.NoError(t, err)
			time.Sleep(10 * time.Millisecond) // Ensure different timestamps
		}
	})

	t.Run("GetPasswordHistory_All", func(t *testing.T) {
		history, err := repo.GetPasswordHistory(ctx, PasswordHistoryParams{
			LoginID: loginID,
			Limit:   0, // No limit
		})
		require.NoError(t, err)
		assert.Len(t, history, 5)

		// Should be sorted by created_at desc (newest first)
		for i := 0; i < len(history)-1; i++ {
			assert.True(t, history[i].CreatedAt.After(history[i+1].CreatedAt) ||
				history[i].CreatedAt.Equal(history[i+1].CreatedAt))
		}
	})

	t.Run("GetPasswordHistory_Limited", func(t *testing.T) {
		history, err := repo.GetPasswordHistory(ctx, PasswordHistoryParams{
			LoginID: loginID,
			Limit:   3,
		})
		require.NoError(t, err)
		assert.Len(t, history, 3)
	})

	t.Run("GetPasswordHistory_NoHistory", func(t *testing.T) {
		history, err := repo.GetPasswordHistory(ctx, PasswordHistoryParams{
			LoginID: uuid.New(),
			Limit:   5,
		})
		require.NoError(t, err)
		assert.Empty(t, history)
	})
}

// Test login attempt tracking
func TestFileLoginRepository_LoginAttempts(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	t.Run("RecordLoginAttempt", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			err := repo.RecordLoginAttempt(ctx, LoginAttempt{
				LoginID: uuid.NullUUID{UUID: loginID, Valid: true},
				Success: false,
			})
			require.NoError(t, err)
		}
	})

	t.Run("GetRecentFailedAttempts", func(t *testing.T) {
		count, err := repo.GetRecentFailedAttempts(ctx, loginID, time.Now().UTC().Add(-1*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})
}

// Test account locking
func TestFileLoginRepository_AccountLocking(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	login := createTestLogin("lockeduser", []byte("password"))

	repo.mutex.Lock()
	repo.logins[login.ID] = &login
	repo.mutex.Unlock()

	t.Run("IsAccountLocked_NotLocked", func(t *testing.T) {
		locked, err := repo.IsAccountLocked(ctx, login.ID)
		require.NoError(t, err)
		assert.False(t, locked)
	})

	t.Run("IncrementFailedLoginAttempts", func(t *testing.T) {
		err := repo.IncrementFailedLoginAttempts(ctx, login.ID)
		require.NoError(t, err)

		attempts, lastFailed, _, err := repo.GetFailedLoginAttempts(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, int32(1), attempts)
		assert.False(t, lastFailed.IsZero())
	})

	t.Run("LockAccount", func(t *testing.T) {
		err := repo.LockAccount(ctx, login.ID, 15*time.Minute)
		require.NoError(t, err)

		locked, err := repo.IsAccountLocked(ctx, login.ID)
		require.NoError(t, err)
		assert.True(t, locked)
	})

	t.Run("ResetFailedLoginAttempts", func(t *testing.T) {
		err := repo.ResetFailedLoginAttempts(ctx, login.ID)
		require.NoError(t, err)

		attempts, _, _, err := repo.GetFailedLoginAttempts(ctx, login.ID)
		require.NoError(t, err)
		assert.Equal(t, int32(0), attempts)
	})
}

// Test passwordless authentication
func TestFileLoginRepository_Passwordless(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	login := createTestLogin("passwordlessuser", nil)

	repo.mutex.Lock()
	repo.logins[login.ID] = &login
	repo.mutex.Unlock()

	t.Run("IsPasswordlessLogin_Default", func(t *testing.T) {
		isPasswordless, err := repo.IsPasswordlessLogin(ctx, login.ID)
		require.NoError(t, err)
		assert.False(t, isPasswordless)
	})

	t.Run("SetPasswordlessFlag", func(t *testing.T) {
		err := repo.SetPasswordlessFlag(ctx, login.ID, true)
		require.NoError(t, err)

		isPasswordless, err := repo.IsPasswordlessLogin(ctx, login.ID)
		require.NoError(t, err)
		assert.True(t, isPasswordless)
	})
}

// Test magic link tokens
func TestFileLoginRepository_MagicLinkToken(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()
	token := "magic_link_token_123"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	t.Run("GenerateMagicLinkToken", func(t *testing.T) {
		err := repo.GenerateMagicLinkToken(ctx, loginID, token, expiresAt)
		require.NoError(t, err)
	})

	t.Run("ValidateMagicLinkToken_Success", func(t *testing.T) {
		retrievedLoginID, err := repo.ValidateMagicLinkToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, loginID, retrievedLoginID)
	})

	t.Run("MarkMagicLinkTokenUsed", func(t *testing.T) {
		err := repo.MarkMagicLinkTokenUsed(ctx, token)
		require.NoError(t, err)

		// Should now fail validation
		_, err = repo.ValidateMagicLinkToken(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token already used")
	})

	t.Run("ExpiredMagicLinkToken", func(t *testing.T) {
		expiredToken := "expired_magic_token"
		err := repo.GenerateMagicLinkToken(ctx, loginID, expiredToken, time.Now().UTC().Add(-1*time.Hour))
		require.NoError(t, err)

		_, err = repo.ValidateMagicLinkToken(ctx, expiredToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired token")
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		_, err := repo.ValidateMagicLinkToken(ctx, "nonexistent_token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")
	})
}

// Test WithTx
func TestFileLoginRepository_WithTx(t *testing.T) {
	repo, _ := setupTestRepo(t)

	// File-based repo returns self
	txRepo := repo.WithTx(nil)
	assert.Equal(t, repo, txRepo)
}

// Test persistence
func TestFileLoginRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "login-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	login := createTestLogin("persistuser", []byte("password"))

	// Create repository and add data
	repo1, err := NewFileLoginRepository(tempDir)
	require.NoError(t, err)

	repo1.mutex.Lock()
	repo1.logins[login.ID] = &login
	err = repo1.save()
	repo1.mutex.Unlock()
	require.NoError(t, err)

	// Create new repository from same directory
	repo2, err := NewFileLoginRepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	foundLogin, err := repo2.GetLoginById(ctx, login.ID)
	require.NoError(t, err)
	assert.Equal(t, login.ID, foundLogin.ID)
	assert.Equal(t, login.Username, foundLogin.Username)
}

// Test concurrent access
func TestFileLoginRepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentWrites", func(t *testing.T) {
		// Create initial logins
		logins := make(map[uuid.UUID]LoginEntity)
		for i := 0; i < numGoroutines; i++ {
			login := createTestLogin("user"+string(rune(i)), []byte("password"))
			logins[login.ID] = login
			repo.mutex.Lock()
			repo.logins[login.ID] = &login
			repo.mutex.Unlock()
		}

		// Concurrent password updates
		wg.Add(numGoroutines)
		for loginID := range logins {
			go func(id uuid.UUID) {
				defer wg.Done()
				_ = repo.ResetPasswordById(ctx, PasswordParams{
					ID:       id,
					Password: []byte("new_password"),
				})
			}(loginID)
		}
		wg.Wait()

		// Verify all were updated
		for loginID := range logins {
			login, err := repo.GetLoginById(ctx, loginID)
			require.NoError(t, err)
			assert.Equal(t, []byte("new_password"), login.Password)
		}
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		login := createTestLogin("readuser", []byte("password"))

		repo.mutex.Lock()
		repo.logins[login.ID] = &login
		repo.mutex.Unlock()

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.GetLoginById(ctx, login.ID)
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
		testLogin := createTestLogin("mixeduser", []byte("initial"))

		repo.mutex.Lock()
		repo.logins[testLogin.ID] = &testLogin
		repo.mutex.Unlock()

		wg.Add(numGoroutines * 2)

		// Writers
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				_ = repo.ResetPasswordById(ctx, PasswordParams{
					ID:       testLogin.ID,
					Password: []byte("password" + string(rune(index))),
				})
			}(i)
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.GetLoginById(ctx, testLogin.ID)
			}()
		}

		wg.Wait()

		// Verify final state exists
		login, err := repo.GetLoginById(ctx, testLogin.ID)
		require.NoError(t, err)
		assert.NotEqual(t, []byte("initial"), login.Password)
	})
}

// Test save/load
func TestFileLoginRepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)

	// Add multiple logins
	for i := 0; i < 3; i++ {
		login := createTestLogin("user"+string(rune(i)), []byte("password"))
		repo.mutex.Lock()
		repo.logins[login.ID] = &login
		repo.mutex.Unlock()
	}

	initialCount := len(repo.logins)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.logins = make(map[uuid.UUID]*LoginEntity)
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialCount, len(repo.logins))
}

// Test empty data
func TestFileLoginRepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository operations should return appropriate errors/empty results
	_, err := repo.GetLoginById(ctx, uuid.New())
	assert.Error(t, err)

	_, err = repo.FindLoginByUsername(ctx, "nonexistent", true)
	assert.Error(t, err)

	history, err := repo.GetPasswordHistory(ctx, PasswordHistoryParams{
		LoginID: uuid.New(),
		Limit:   5,
	})
	require.NoError(t, err)
	assert.Empty(t, history)

	count, err := repo.GetRecentFailedAttempts(ctx, uuid.New(), time.Now().UTC().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// Test login attempts limit
func TestFileLoginRepository_LoginAttemptsLimit(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Add more than 10000 attempts
	for i := 0; i < 10100; i++ {
		err := repo.RecordLoginAttempt(ctx, LoginAttempt{
			LoginID: uuid.NullUUID{UUID: loginID, Valid: true},
			Success: false,
		})
		require.NoError(t, err)
	}

	// Should have trimmed to 10000
	assert.LessOrEqual(t, len(repo.loginAttempts), 10000)
}

// Test methods that require database JOIN (should return errors or empty results)
func TestFileLoginRepository_UnsupportedMethods(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	t.Run("FindLoginsByEmail_Unsupported", func(t *testing.T) {
		logins, err := repo.FindLoginsByEmail(ctx, "test@example.com")
		require.NoError(t, err)
		assert.Empty(t, logins) // Not supported in file mode
	})

	t.Run("FindPrimaryLoginByEmail_Unsupported", func(t *testing.T) {
		_, err := repo.FindPrimaryLoginByEmail(ctx, "test@example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported in file mode")
	})

	t.Run("InitPasswordByUsername", func(t *testing.T) {
		login := createTestLogin("inituser", []byte("password"))
		repo.mutex.Lock()
		repo.logins[login.ID] = &login
		repo.mutex.Unlock()

		loginID, err := repo.InitPasswordByUsername(ctx, "inituser", true)
		require.NoError(t, err)
		assert.Equal(t, login.ID, loginID)
	})
}
