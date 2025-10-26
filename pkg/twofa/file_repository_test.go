package twofa

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestRepo creates a temporary directory and repository for testing
func setupTestRepo(t *testing.T) (*FileTwoFARepository, string) {
	tempDir := filepath.Join(os.TempDir(), "twofa-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	repo, err := NewFileTwoFARepository(tempDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

func TestFileTwoFARepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "twofa-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	// Should create directory if it doesn't exist
	repo, err := NewFileTwoFARepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileTwoFARepository_Create2FAInit(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	t.Run("Success", func(t *testing.T) {
		params := Create2FAParams{
			LoginID:              loginID,
			TwoFactorSecret:      "secret123",
			SecretValid:          true,
			TwoFactorType:        "totp",
			TypeValid:            true,
			TwoFactorEnabled:     false,
			EnabledValid:         true,
			TwoFactorBackupCodes: []string{"code1", "code2"},
		}

		id, err := repo.Create2FAInit(ctx, params)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, id)

		// Verify it was created
		twofa, err := repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            id,
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)
		assert.Equal(t, "secret123", twofa.TwoFactorSecret)
		assert.False(t, twofa.TwoFactorEnabled)
	})

	t.Run("MultipleTypesPerLogin", func(t *testing.T) {
		// Create TOTP 2FA
		totpParams := Create2FAParams{
			LoginID:          loginID,
			TwoFactorSecret:  "totp_secret",
			SecretValid:      true,
			TwoFactorType:    "totp",
			TypeValid:        true,
			TwoFactorEnabled: true,
			EnabledValid:     true,
		}
		totpID, err := repo.Create2FAInit(ctx, totpParams)
		require.NoError(t, err)

		// Create SMS 2FA
		smsParams := Create2FAParams{
			LoginID:          loginID,
			TwoFactorSecret:  "sms_secret",
			SecretValid:      true,
			TwoFactorType:    "sms",
			TypeValid:        true,
			TwoFactorEnabled: false,
			EnabledValid:     true,
		}
		smsID, err := repo.Create2FAInit(ctx, smsParams)
		require.NoError(t, err)

		assert.NotEqual(t, totpID, smsID)

		// Both should exist
		twofas, err := repo.FindTwoFAsByLoginID(ctx, loginID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(twofas), 2)
	})
}

func TestFileTwoFARepository_Enable2FA(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Create disabled 2FA
	params := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "secret",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: false,
		EnabledValid:     true,
	}
	id, err := repo.Create2FAInit(ctx, params)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.Enable2FA(ctx, Enable2FAParams{
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)

		// Verify it's enabled
		twofa, err := repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            id,
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)
		assert.True(t, twofa.TwoFactorEnabled)
	})

	t.Run("NotFound", func(t *testing.T) {
		err := repo.Enable2FA(ctx, Enable2FAParams{
			LoginID:       uuid.New(),
			TwoFactorType: "nonexistent",
		})
		assert.Error(t, err)
	})
}

func TestFileTwoFARepository_Disable2FA(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Create enabled 2FA
	params := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "secret",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: true,
		EnabledValid:     true,
	}
	id, err := repo.Create2FAInit(ctx, params)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.Disable2FA(ctx, Disable2FAParams{
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)

		// Verify it's disabled
		twofa, err := repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            id,
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)
		assert.False(t, twofa.TwoFactorEnabled)
	})
}

func TestFileTwoFARepository_Delete2FA(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Create 2FA
	params := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "secret",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: true,
		EnabledValid:     true,
	}
	id, err := repo.Create2FAInit(ctx, params)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.Delete2FA(ctx, Delete2FAParams{
			ID:            id,
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)

		// Verify it's deleted (hard delete in file repository)
		_, err = repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            id,
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		assert.Error(t, err)
	})
}

func TestFileTwoFARepository_Get2FAByID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	params := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "secret123",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: true,
		EnabledValid:     true,
	}
	id, err := repo.Create2FAInit(ctx, params)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		twofa, err := repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            id,
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)
		assert.Equal(t, id, twofa.ID)
		assert.Equal(t, loginID, twofa.LoginID)
		assert.Equal(t, "secret123", twofa.TwoFactorSecret)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            uuid.New(),
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		assert.Error(t, err)
	})

	t.Run("LoginIDMismatch", func(t *testing.T) {
		_, err := repo.Get2FAByID(ctx, Get2FAByIDParams{
			ID:            id,
			LoginID:       uuid.New(), // Wrong login ID
			TwoFactorType: "totp",
		})
		assert.Error(t, err)
	})
}

func TestFileTwoFARepository_Get2FAByLoginID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	params := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "secret",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: true,
		EnabledValid:     true,
	}
	_, err := repo.Create2FAInit(ctx, params)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		twofa, err := repo.Get2FAByLoginID(ctx, Get2FAByLoginIDParams{
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)
		assert.Equal(t, loginID, twofa.LoginID)
		assert.Equal(t, "totp", twofa.TwoFactorType)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := repo.Get2FAByLoginID(ctx, Get2FAByLoginIDParams{
			LoginID:       uuid.New(),
			TwoFactorType: "totp",
		})
		assert.Error(t, err)
	})
}

func TestFileTwoFARepository_FindTwoFAsByLoginID(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Create multiple 2FA methods
	types := []string{"totp", "sms", "email"}
	for _, tfType := range types {
		params := Create2FAParams{
			LoginID:          loginID,
			TwoFactorSecret:  "secret_" + tfType,
			SecretValid:      true,
			TwoFactorType:    tfType,
			TypeValid:        true,
			TwoFactorEnabled: true,
			EnabledValid:     true,
		}
		_, err := repo.Create2FAInit(ctx, params)
		require.NoError(t, err)
	}

	t.Run("FindAll", func(t *testing.T) {
		twofas, err := repo.FindTwoFAsByLoginID(ctx, loginID)
		require.NoError(t, err)
		assert.Len(t, twofas, 3)

		// Verify all types are present
		foundTypes := make(map[string]bool)
		for _, twofa := range twofas {
			foundTypes[twofa.TwoFactorType] = true
		}
		assert.True(t, foundTypes["totp"])
		assert.True(t, foundTypes["sms"])
		assert.True(t, foundTypes["email"])
	})

	t.Run("NoResults", func(t *testing.T) {
		twofas, err := repo.FindTwoFAsByLoginID(ctx, uuid.New())
		require.NoError(t, err)
		assert.Empty(t, twofas)
	})
}

func TestFileTwoFARepository_FindEnabledTwoFAs(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	loginID := uuid.New()

	// Create enabled and disabled 2FA methods
	enabledParams := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "enabled_secret",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: true,
		EnabledValid:     true,
	}
	_, err := repo.Create2FAInit(ctx, enabledParams)
	require.NoError(t, err)

	disabledParams := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "disabled_secret",
		SecretValid:      true,
		TwoFactorType:    "sms",
		TypeValid:        true,
		TwoFactorEnabled: false,
		EnabledValid:     true,
	}
	_, err = repo.Create2FAInit(ctx, disabledParams)
	require.NoError(t, err)

	t.Run("OnlyEnabled", func(t *testing.T) {
		twofas, err := repo.FindEnabledTwoFAs(ctx, loginID)
		require.NoError(t, err)
		assert.Len(t, twofas, 1)
		assert.Equal(t, "totp", twofas[0].TwoFactorType)
		assert.True(t, twofas[0].TwoFactorEnabled)
	})
}

func TestFileTwoFARepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "twofa-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	loginID := uuid.New()

	params := Create2FAParams{
		LoginID:          loginID,
		TwoFactorSecret:  "persist_secret",
		SecretValid:      true,
		TwoFactorType:    "totp",
		TypeValid:        true,
		TwoFactorEnabled: true,
		EnabledValid:     true,
	}

	// Create repository and add data
	repo1, err := NewFileTwoFARepository(tempDir)
	require.NoError(t, err)

	id, err := repo1.Create2FAInit(ctx, params)
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileTwoFARepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	twofa, err := repo2.Get2FAByID(ctx, Get2FAByIDParams{
		ID:            id,
		LoginID:       loginID,
		TwoFactorType: "totp",
	})
	require.NoError(t, err)
	assert.Equal(t, "persist_secret", twofa.TwoFactorSecret)
	assert.True(t, twofa.TwoFactorEnabled)
}

func TestFileTwoFARepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentCreates", func(t *testing.T) {
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				params := Create2FAParams{
					LoginID:          uuid.New(),
					TwoFactorSecret:  "secret",
					SecretValid:      true,
					TwoFactorType:    "totp",
					TypeValid:        true,
					TwoFactorEnabled: false,
					EnabledValid:     true,
				}
				_, _ = repo.Create2FAInit(ctx, params)
			}(i)
		}
		wg.Wait()

		// Should have created many 2FA records
		assert.GreaterOrEqual(t, len(repo.twofas), numGoroutines)
	})

	t.Run("ConcurrentEnableDisable", func(t *testing.T) {
		loginID := uuid.New()
		params := Create2FAParams{
			LoginID:          loginID,
			TwoFactorSecret:  "toggle_secret",
			SecretValid:      true,
			TwoFactorType:    "totp",
			TypeValid:        true,
			TwoFactorEnabled: false,
			EnabledValid:     true,
		}
		_, err := repo.Create2FAInit(ctx, params)
		require.NoError(t, err)

		wg.Add(numGoroutines * 2)

		// Concurrent enables
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_ = repo.Enable2FA(ctx, Enable2FAParams{
					LoginID:       loginID,
					TwoFactorType: "totp",
				})
			}()
		}

		// Concurrent disables
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_ = repo.Disable2FA(ctx, Disable2FAParams{
					LoginID:       loginID,
					TwoFactorType: "totp",
				})
			}()
		}

		wg.Wait()

		// Should be in a consistent state (either enabled or disabled)
		twofa, err := repo.Get2FAByLoginID(ctx, Get2FAByLoginIDParams{
			LoginID:       loginID,
			TwoFactorType: "totp",
		})
		require.NoError(t, err)
		assert.True(t, twofa.EnabledValid) // Valid flag should be set
	})
}

func TestFileTwoFARepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Create multiple 2FA records
	for i := 0; i < 3; i++ {
		params := Create2FAParams{
			LoginID:          uuid.New(),
			TwoFactorSecret:  "secret",
			SecretValid:      true,
			TwoFactorType:    "totp",
			TypeValid:        true,
			TwoFactorEnabled: true,
			EnabledValid:     true,
		}
		_, err := repo.Create2FAInit(ctx, params)
		require.NoError(t, err)
	}

	initialCount := len(repo.twofas)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.twofas = make(map[uuid.UUID]TwoFAEntity)
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialCount, len(repo.twofas))
}

func TestFileTwoFARepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository operations should not error
	twofas, err := repo.FindTwoFAsByLoginID(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, twofas)

	twofas, err = repo.FindEnabledTwoFAs(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, twofas)
}
