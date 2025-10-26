package delegate

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/mapper"
)

// mockUserMapper implements mapper.UserMapper for testing
type mockUserMapper struct {
	users map[uuid.UUID]mapper.User
	mutex sync.RWMutex
}

func newMockUserMapper() *mockUserMapper {
	return &mockUserMapper{
		users: make(map[uuid.UUID]mapper.User),
	}
}

func (m *mockUserMapper) FindUsersByLoginID(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	return nil, nil
}

func (m *mockUserMapper) GetUserByUserID(ctx context.Context, userID uuid.UUID) (mapper.User, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	user, exists := m.users[userID]
	if !exists {
		return mapper.User{}, assert.AnError // Return error when not found
	}

	return user, nil
}

func (m *mockUserMapper) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	return nil, nil
}

func (m *mockUserMapper) ToTokenClaims(user mapper.User) (map[string]interface{}, map[string]interface{}) {
	return nil, nil
}

func (m *mockUserMapper) ExtractTokenClaims(user mapper.User, claims map[string]interface{}) mapper.User {
	return user
}

func (m *mockUserMapper) addUser(user mapper.User) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	userID, _ := uuid.Parse(user.UserId)
	m.users[userID] = user
}

// setupTestRepo creates a temporary directory and repository for testing
func setupTestRepo(t *testing.T) (*FileDelegationRepository, *mockUserMapper, string) {
	tempDir := filepath.Join(os.TempDir(), "delegate-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	userMapper := newMockUserMapper()
	repo, err := NewFileDelegationRepository(tempDir, userMapper)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return repo, userMapper, tempDir
}

// createTestUser creates a test user
func createTestUser(userID uuid.UUID, email string) mapper.User {
	return mapper.User{
		UserId: userID.String(),
		UserInfo: mapper.UserInfo{
			Email: email,
		},
	}
}

func TestFileDelegationRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "delegate-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	userMapper := newMockUserMapper()

	// Should create directory if it doesn't exist
	repo, err := NewFileDelegationRepository(tempDir, userMapper)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileDelegationRepository_AddDelegation(t *testing.T) {
	repo, userMapper, _ := setupTestRepo(t)
	ctx := context.Background()

	delegatorID := uuid.New()
	delegateeID := uuid.New()

	// Add test users to mapper
	userMapper.addUser(createTestUser(delegatorID, "delegator@example.com"))
	userMapper.addUser(createTestUser(delegateeID, "delegatee@example.com"))

	t.Run("Success", func(t *testing.T) {
		err := repo.AddDelegation(ctx, delegatorID, delegateeID)
		require.NoError(t, err)

		// Verify delegation was added
		delegators, err := repo.FindDelegators(ctx, delegateeID)
		require.NoError(t, err)
		assert.Len(t, delegators, 1)
		assert.Equal(t, delegatorID.String(), delegators[0].UserId)
	})

	t.Run("DuplicateDelegation", func(t *testing.T) {
		// Try to add the same delegation again
		err := repo.AddDelegation(ctx, delegatorID, delegateeID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delegation already exists")
	})

	t.Run("MultipleDelegators", func(t *testing.T) {
		delegator2ID := uuid.New()
		userMapper.addUser(createTestUser(delegator2ID, "delegator2@example.com"))

		err := repo.AddDelegation(ctx, delegator2ID, delegateeID)
		require.NoError(t, err)

		delegators, err := repo.FindDelegators(ctx, delegateeID)
		require.NoError(t, err)
		assert.Len(t, delegators, 2)
	})
}

func TestFileDelegationRepository_FindDelegators(t *testing.T) {
	repo, userMapper, _ := setupTestRepo(t)
	ctx := context.Background()

	delegateeID := uuid.New()
	delegator1ID := uuid.New()
	delegator2ID := uuid.New()

	// Add test users
	userMapper.addUser(createTestUser(delegator1ID, "delegator1@example.com"))
	userMapper.addUser(createTestUser(delegator2ID, "delegator2@example.com"))

	// Add delegations
	err := repo.AddDelegation(ctx, delegator1ID, delegateeID)
	require.NoError(t, err)
	err = repo.AddDelegation(ctx, delegator2ID, delegateeID)
	require.NoError(t, err)

	t.Run("FindMultipleDelegators", func(t *testing.T) {
		delegators, err := repo.FindDelegators(ctx, delegateeID)
		require.NoError(t, err)
		assert.Len(t, delegators, 2)

		// Check that both delegators are present
		delegatorIDs := make(map[string]bool)
		for _, user := range delegators {
			delegatorIDs[user.UserId] = true
		}
		assert.True(t, delegatorIDs[delegator1ID.String()])
		assert.True(t, delegatorIDs[delegator2ID.String()])
	})

	t.Run("NoDelegators", func(t *testing.T) {
		nonExistentID := uuid.New()
		delegators, err := repo.FindDelegators(ctx, nonExistentID)
		require.NoError(t, err)
		assert.Empty(t, delegators)
	})

	t.Run("DelegatorNotInMapper", func(t *testing.T) {
		// Add delegation for a user not in the mapper
		delegatee2ID := uuid.New()
		nonExistentDelegatorID := uuid.New()
		err := repo.AddDelegation(ctx, nonExistentDelegatorID, delegatee2ID)
		require.NoError(t, err)

		// Should return empty list (delegator not found in mapper)
		delegators, err := repo.FindDelegators(ctx, delegatee2ID)
		require.NoError(t, err)
		assert.Empty(t, delegators)
	})
}

func TestFileDelegationRepository_RemoveDelegation(t *testing.T) {
	repo, userMapper, _ := setupTestRepo(t)
	ctx := context.Background()

	delegatorID := uuid.New()
	delegateeID := uuid.New()

	// Add test users
	userMapper.addUser(createTestUser(delegatorID, "delegator@example.com"))
	userMapper.addUser(createTestUser(delegateeID, "delegatee@example.com"))

	// Add delegation
	err := repo.AddDelegation(ctx, delegatorID, delegateeID)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.RemoveDelegation(ctx, delegatorID, delegateeID)
		require.NoError(t, err)

		// Verify delegation was removed
		delegators, err := repo.FindDelegators(ctx, delegateeID)
		require.NoError(t, err)
		assert.Empty(t, delegators)
	})

	t.Run("DelegationNotFound", func(t *testing.T) {
		// Try to remove non-existent delegation
		err := repo.RemoveDelegation(ctx, uuid.New(), uuid.New())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delegation not found")
	})
}

func TestFileDelegationRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "delegate-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	delegatorID := uuid.New()
	delegateeID := uuid.New()

	userMapper1 := newMockUserMapper()
	userMapper1.addUser(createTestUser(delegatorID, "delegator@example.com"))

	// Create repository and add delegation
	repo1, err := NewFileDelegationRepository(tempDir, userMapper1)
	require.NoError(t, err)

	err = repo1.AddDelegation(ctx, delegatorID, delegateeID)
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	userMapper2 := newMockUserMapper()
	userMapper2.addUser(createTestUser(delegatorID, "delegator@example.com"))

	repo2, err := NewFileDelegationRepository(tempDir, userMapper2)
	require.NoError(t, err)

	// Data should be loaded
	delegators, err := repo2.FindDelegators(ctx, delegateeID)
	require.NoError(t, err)
	assert.Len(t, delegators, 1)
	assert.Equal(t, delegatorID.String(), delegators[0].UserId)
}

func TestFileDelegationRepository_ConcurrentAccess(t *testing.T) {
	repo, userMapper, _ := setupTestRepo(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentWrites", func(t *testing.T) {
		delegateeID := uuid.New()

		// Create delegators
		delegatorIDs := make([]uuid.UUID, numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			delegatorIDs[i] = uuid.New()
			userMapper.addUser(createTestUser(delegatorIDs[i], "delegator@example.com"))
		}

		// Concurrent delegation additions
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				_ = repo.AddDelegation(ctx, delegatorIDs[index], delegateeID)
			}(i)
		}
		wg.Wait()

		// Verify all delegations were added
		delegators, err := repo.FindDelegators(ctx, delegateeID)
		require.NoError(t, err)
		assert.Len(t, delegators, numGoroutines)
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		delegateeID := uuid.New()
		delegatorID := uuid.New()
		userMapper.addUser(createTestUser(delegatorID, "delegator@example.com"))

		err := repo.AddDelegation(ctx, delegatorID, delegateeID)
		require.NoError(t, err)

		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, err := repo.FindDelegators(ctx, delegateeID)
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
		testDelegateeID := uuid.New()
		testDelegatorID := uuid.New()
		userMapper.addUser(createTestUser(testDelegatorID, "delegator@example.com"))

		err := repo.AddDelegation(ctx, testDelegatorID, testDelegateeID)
		require.NoError(t, err)

		wg.Add(numGoroutines * 2)

		// Writers (add more delegators)
		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				newDelegatorID := uuid.New()
				userMapper.addUser(createTestUser(newDelegatorID, "delegator@example.com"))
				_ = repo.AddDelegation(ctx, newDelegatorID, testDelegateeID)
			}(i)
		}

		// Readers
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.FindDelegators(ctx, testDelegateeID)
			}()
		}

		wg.Wait()

		// Verify final state has at least the initial delegation
		delegators, err := repo.FindDelegators(ctx, testDelegateeID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(delegators), 1)
	})
}

func TestFileDelegationRepository_SaveLoad(t *testing.T) {
	repo, userMapper, _ := setupTestRepo(t)
	ctx := context.Background()

	// Add multiple delegations
	delegateeID := uuid.New()
	for i := 0; i < 3; i++ {
		delegatorID := uuid.New()
		userMapper.addUser(createTestUser(delegatorID, "delegator@example.com"))
		err := repo.AddDelegation(ctx, delegatorID, delegateeID)
		require.NoError(t, err)
	}

	initialCount := len(repo.delegations)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.delegations = []DelegationRecord{}
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialCount, len(repo.delegations))

	// Verify data integrity
	delegators, err := repo.FindDelegators(ctx, delegateeID)
	require.NoError(t, err)
	assert.Len(t, delegators, 3)
}

func TestFileDelegationRepository_EmptyData(t *testing.T) {
	repo, _, _ := setupTestRepo(t)
	ctx := context.Background()

	// Empty repository operations should return empty results
	delegators, err := repo.FindDelegators(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, delegators)

	// Removing non-existent delegation should error
	err = repo.RemoveDelegation(ctx, uuid.New(), uuid.New())
	assert.Error(t, err)
}
