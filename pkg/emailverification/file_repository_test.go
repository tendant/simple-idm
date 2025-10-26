package emailverification

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
func setupTestRepo(t *testing.T) (*FileEmailVerificationRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "emailverification-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	repo, err := NewFileEmailVerificationRepository(tempDir)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, tempDir
}

func TestFileEmailVerificationRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "emailverification-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	// Should create directory if it doesn't exist
	repo, err := NewFileEmailVerificationRepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileEmailVerificationRepository_CreateVerificationToken(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	token := "test_token_123"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	t.Run("Success", func(t *testing.T) {
		vt, err := repo.CreateVerificationToken(ctx, userID, token, expiresAt)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, vt.ID)
		assert.Equal(t, userID, vt.UserID)
		assert.Equal(t, token, vt.Token)
		assert.Nil(t, vt.VerifiedAt)
		assert.Nil(t, vt.DeletedAt)
	})

	t.Run("MultipleTokensForSameUser", func(t *testing.T) {
		token2 := "test_token_456"
		vt2, err := repo.CreateVerificationToken(ctx, userID, token2, expiresAt)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, vt2.ID)
		assert.Equal(t, token2, vt2.Token)

		// Should have 2 tokens for this user
		tokens, err := repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})
}

func TestFileEmailVerificationRepository_GetVerificationTokenByToken(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	token := "test_token_123"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	vt, err := repo.CreateVerificationToken(ctx, userID, token, expiresAt)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		foundToken, err := repo.GetVerificationTokenByToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, vt.ID, foundToken.ID)
		assert.Equal(t, token, foundToken.Token)
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		_, err := repo.GetVerificationTokenByToken(ctx, "nonexistent_token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "verification token not found")
	})

	t.Run("VerifiedTokenNotReturned", func(t *testing.T) {
		// Mark token as verified
		err := repo.MarkTokenAsVerified(ctx, vt.ID)
		require.NoError(t, err)

		// Should not find it anymore (only returns active tokens)
		_, err = repo.GetVerificationTokenByToken(ctx, token)
		assert.Error(t, err)
	})

	t.Run("DeletedTokenNotReturned", func(t *testing.T) {
		token2 := "test_token_456"
		vt2, err := repo.CreateVerificationToken(ctx, userID, token2, expiresAt)
		require.NoError(t, err)

		// Soft delete the token
		err = repo.SoftDeleteToken(ctx, vt2.ID)
		require.NoError(t, err)

		// Should not find it anymore
		_, err = repo.GetVerificationTokenByToken(ctx, token2)
		assert.Error(t, err)
	})
}

func TestFileEmailVerificationRepository_GetActiveTokensByUserId(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	t.Run("MultipleActiveTokens", func(t *testing.T) {
		// Create 3 tokens
		_, err := repo.CreateVerificationToken(ctx, userID, "token1", expiresAt)
		require.NoError(t, err)
		_, err = repo.CreateVerificationToken(ctx, userID, "token2", expiresAt)
		require.NoError(t, err)
		vt3, err := repo.CreateVerificationToken(ctx, userID, "token3", expiresAt)
		require.NoError(t, err)

		tokens, err := repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, tokens, 3)

		// Verify one token
		err = repo.MarkTokenAsVerified(ctx, vt3.ID)
		require.NoError(t, err)

		// Should now have only 2 active tokens
		tokens, err = repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})

	t.Run("NoActiveTokens", func(t *testing.T) {
		newUserID := uuid.New()
		tokens, err := repo.GetActiveTokensByUserId(ctx, newUserID)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})
}

func TestFileEmailVerificationRepository_MarkTokenAsVerified(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	token := "test_token_123"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	vt, err := repo.CreateVerificationToken(ctx, userID, token, expiresAt)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		before := time.Now().UTC()
		err := repo.MarkTokenAsVerified(ctx, vt.ID)
		require.NoError(t, err)
		after := time.Now().UTC()

		// Verify the timestamp was set
		repo.mutex.RLock()
		verifiedToken := repo.tokens[vt.ID]
		repo.mutex.RUnlock()

		assert.NotNil(t, verifiedToken.VerifiedAt)
		assert.True(t, verifiedToken.VerifiedAt.After(before) || verifiedToken.VerifiedAt.Equal(before))
		assert.True(t, verifiedToken.VerifiedAt.Before(after) || verifiedToken.VerifiedAt.Equal(after))
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		err := repo.MarkTokenAsVerified(ctx, uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")
	})
}

func TestFileEmailVerificationRepository_SoftDeleteToken(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	token := "test_token_123"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	vt, err := repo.CreateVerificationToken(ctx, userID, token, expiresAt)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		before := time.Now().UTC()
		err := repo.SoftDeleteToken(ctx, vt.ID)
		require.NoError(t, err)
		after := time.Now().UTC()

		// Verify the timestamp was set
		repo.mutex.RLock()
		deletedToken := repo.tokens[vt.ID]
		repo.mutex.RUnlock()

		assert.NotNil(t, deletedToken.DeletedAt)
		assert.True(t, deletedToken.DeletedAt.After(before) || deletedToken.DeletedAt.Equal(before))
		assert.True(t, deletedToken.DeletedAt.Before(after) || deletedToken.DeletedAt.Equal(after))

		// Token should not be returned by GetActiveTokensByUserId
		tokens, err := repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		err := repo.SoftDeleteToken(ctx, uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")
	})
}

func TestFileEmailVerificationRepository_SoftDeleteUserTokens(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	// Create multiple tokens for the user
	_, err := repo.CreateVerificationToken(ctx, userID, "token1", expiresAt)
	require.NoError(t, err)
	_, err = repo.CreateVerificationToken(ctx, userID, "token2", expiresAt)
	require.NoError(t, err)
	_, err = repo.CreateVerificationToken(ctx, userID, "token3", expiresAt)
	require.NoError(t, err)

	// Create tokens for another user
	otherUserID := uuid.New()
	_, err = repo.CreateVerificationToken(ctx, otherUserID, "other_token", expiresAt)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.SoftDeleteUserTokens(ctx, userID)
		require.NoError(t, err)

		// User's tokens should be deleted
		tokens, err := repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, tokens)

		// Other user's tokens should remain
		otherTokens, err := repo.GetActiveTokensByUserId(ctx, otherUserID)
		require.NoError(t, err)
		assert.Len(t, otherTokens, 1)
	})
}

func TestFileEmailVerificationRepository_MarkUserEmailAsVerified(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("CreateNewUserStatus", func(t *testing.T) {
		before := time.Now().UTC()
		err := repo.MarkUserEmailAsVerified(ctx, userID)
		require.NoError(t, err)
		after := time.Now().UTC()

		// Verify the user status was created
		status, err := repo.GetUserEmailVerificationStatus(ctx, userID)
		require.NoError(t, err)
		assert.True(t, status.EmailVerified)
		assert.NotNil(t, status.EmailVerifiedAt)
		assert.True(t, status.EmailVerifiedAt.After(before) || status.EmailVerifiedAt.Equal(before))
		assert.True(t, status.EmailVerifiedAt.Before(after) || status.EmailVerifiedAt.Equal(after))
	})

	t.Run("UpdateExistingUserStatus", func(t *testing.T) {
		// Mark as verified again
		err := repo.MarkUserEmailAsVerified(ctx, userID)
		require.NoError(t, err)

		status, err := repo.GetUserEmailVerificationStatus(ctx, userID)
		require.NoError(t, err)
		assert.True(t, status.EmailVerified)
	})
}

func TestFileEmailVerificationRepository_GetUserEmailVerificationStatus(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.GetUserEmailVerificationStatus(ctx, userID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})

	t.Run("Success", func(t *testing.T) {
		err := repo.MarkUserEmailAsVerified(ctx, userID)
		require.NoError(t, err)

		status, err := repo.GetUserEmailVerificationStatus(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, userID, status.ID)
		assert.True(t, status.EmailVerified)
	})
}

func TestFileEmailVerificationRepository_CountRecentTokensByUserId(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	t.Run("CountAll", func(t *testing.T) {
		// Create 3 tokens
		_, err := repo.CreateVerificationToken(ctx, userID, "token1", expiresAt)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
		_, err = repo.CreateVerificationToken(ctx, userID, "token2", expiresAt)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
		_, err = repo.CreateVerificationToken(ctx, userID, "token3", expiresAt)
		require.NoError(t, err)

		// Count all tokens (since 1 hour ago)
		count, err := repo.CountRecentTokensByUserId(ctx, userID, time.Now().UTC().Add(-1*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
	})

	t.Run("CountRecent", func(t *testing.T) {
		// Count only tokens created in the last 5 milliseconds
		// The last token was created most recently, so it should be the only one
		count, err := repo.CountRecentTokensByUserId(ctx, userID, time.Now().UTC().Add(-5*time.Millisecond))
		require.NoError(t, err)
		// Depending on timing, could be 0 or 1 (timing is unreliable in tests)
		assert.GreaterOrEqual(t, count, int64(0))
		assert.LessOrEqual(t, count, int64(1))
	})

	t.Run("NoTokens", func(t *testing.T) {
		newUserID := uuid.New()
		count, err := repo.CountRecentTokensByUserId(ctx, newUserID, time.Now().UTC().Add(-1*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func TestFileEmailVerificationRepository_CleanupExpiredTokens(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()

	// Create expired token
	expiredToken, err := repo.CreateVerificationToken(ctx, userID, "expired_token", time.Now().UTC().Add(-1*time.Hour))
	require.NoError(t, err)

	// Create valid token
	validToken, err := repo.CreateVerificationToken(ctx, userID, "valid_token", time.Now().UTC().Add(1*time.Hour))
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.CleanupExpiredTokens(ctx)
		require.NoError(t, err)

		// Expired token should be marked as deleted
		repo.mutex.RLock()
		expiredVT := repo.tokens[expiredToken.ID]
		validVT := repo.tokens[validToken.ID]
		repo.mutex.RUnlock()

		assert.NotNil(t, expiredVT.DeletedAt)
		assert.Nil(t, validVT.DeletedAt)

		// Active tokens should only include the valid one
		tokens, err := repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.Equal(t, validToken.ID, tokens[0].ID)
	})
}

func TestFileEmailVerificationRepository_GetUserByEmail(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	userID := uuid.New()
	email := "test@example.com"

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.GetUserByEmail(ctx, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found with email")
	})

	t.Run("Success", func(t *testing.T) {
		// Create user status with email
		repo.mutex.Lock()
		repo.users[userID] = &UserEmailStatus{
			ID:            userID,
			Email:         email,
			EmailVerified: true,
		}
		repo.mutex.Unlock()

		user, err := repo.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, email, user.Email)
		assert.True(t, user.EmailVerified)
	})
}

func TestFileEmailVerificationRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "emailverification-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	userID := uuid.New()
	token := "persist_token"
	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	// Create repository and add data
	repo1, err := NewFileEmailVerificationRepository(tempDir)
	require.NoError(t, err)

	vt, err := repo1.CreateVerificationToken(ctx, userID, token, expiresAt)
	require.NoError(t, err)

	err = repo1.MarkUserEmailAsVerified(ctx, userID)
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileEmailVerificationRepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	foundToken, err := repo2.GetVerificationTokenByToken(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, vt.ID, foundToken.ID)
	assert.Equal(t, token, foundToken.Token)

	status, err := repo2.GetUserEmailVerificationStatus(ctx, userID)
	require.NoError(t, err)
	assert.True(t, status.EmailVerified)
}

func TestFileEmailVerificationRepository_ConcurrentAccess(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentWrites", func(t *testing.T) {
		userID := uuid.New()
		expiresAt := time.Now().UTC().Add(1 * time.Hour)

		// Concurrent token creations
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				token := "concurrent_token_" + string(rune(index))
				_, _ = repo.CreateVerificationToken(ctx, userID, token, expiresAt)
			}(i)
		}
		wg.Wait()

		// Verify tokens were created
		tokens, err := repo.GetActiveTokensByUserId(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, tokens, numGoroutines)
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		userID := uuid.New()
		token := "read_token"
		expiresAt := time.Now().UTC().Add(1 * time.Hour)

		_, err := repo.CreateVerificationToken(ctx, userID, token, expiresAt)
		require.NoError(t, err)

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.GetVerificationTokenByToken(ctx, token)
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
		testToken := "mixed_token"
		expiresAt := time.Now().UTC().Add(1 * time.Hour)

		vt, err := repo.CreateVerificationToken(ctx, testUserID, testToken, expiresAt)
		require.NoError(t, err)

		wg.Add(numGoroutines * 2)

		// Writers (mark as verified)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_ = repo.MarkTokenAsVerified(ctx, vt.ID)
			}()
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.GetActiveTokensByUserId(ctx, testUserID)
			}()
		}

		wg.Wait()

		// Verify final state
		repo.mutex.RLock()
		verifiedToken := repo.tokens[vt.ID]
		repo.mutex.RUnlock()
		assert.NotNil(t, verifiedToken.VerifiedAt)
	})
}

func TestFileEmailVerificationRepository_SaveLoad(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(1 * time.Hour)

	// Add multiple tokens and user statuses
	for i := 0; i < 3; i++ {
		userID := uuid.New()
		token := "token_" + string(rune(i))
		_, err := repo.CreateVerificationToken(ctx, userID, token, expiresAt)
		require.NoError(t, err)

		err = repo.MarkUserEmailAsVerified(ctx, userID)
		require.NoError(t, err)
	}

	initialTokenCount := len(repo.tokens)
	initialUserCount := len(repo.users)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.tokens = make(map[uuid.UUID]*VerificationToken)
	repo.users = make(map[uuid.UUID]*UserEmailStatus)
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialTokenCount, len(repo.tokens))
	assert.Equal(t, initialUserCount, len(repo.users))
}

func TestFileEmailVerificationRepository_EmptyData(t *testing.T) {
	repo, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository operations should return appropriate errors/empty results
	_, err := repo.GetVerificationTokenByToken(ctx, "nonexistent")
	assert.Error(t, err)

	tokens, err := repo.GetActiveTokensByUserId(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, tokens)

	_, err = repo.GetUserEmailVerificationStatus(ctx, uuid.New())
	assert.Error(t, err)

	count, err := repo.CountRecentTokensByUserId(ctx, uuid.New(), time.Now().UTC().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
