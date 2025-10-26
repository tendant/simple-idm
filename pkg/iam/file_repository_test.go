package iam

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

// setupTestRepos creates temporary directory and both repositories for testing
func setupTestRepos(t *testing.T) (*FileIamRepository, *FileIamGroupRepository, string) {
	tempDir := filepath.Join(os.TempDir(), "iam-test-"+uuid.New().String())
	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	iamRepo, err := NewFileIamRepository(tempDir)
	require.NoError(t, err)

	groupRepo := NewFileIamGroupRepository(iamRepo)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return iamRepo, groupRepo, tempDir
}

// ========== IamRepository Tests ==========

func TestFileIamRepository_NewRepository(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "iam-test-new-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	repo, err := NewFileIamRepository(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, repo)
	assert.DirExists(t, tempDir)
}

func TestFileIamRepository_CreateUser(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		loginID := uuid.New()
		params := CreateUserParams{
			Email:   "test@example.com",
			Name:    "Test User",
			LoginID: &loginID,
		}

		user, err := repo.CreateUser(ctx, params)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, user.ID)
		assert.Equal(t, params.Email, user.Email)
		assert.Equal(t, params.Name, user.Name)
		assert.NotNil(t, user.LoginID)
		assert.Equal(t, loginID, *user.LoginID)
		assert.Nil(t, user.DeletedAt)
	})

	t.Run("WithoutLoginID", func(t *testing.T) {
		params := CreateUserParams{
			Email: "noLoginId@example.com",
			Name:  "No Login",
		}

		user, err := repo.CreateUser(ctx, params)
		require.NoError(t, err)
		assert.Nil(t, user.LoginID)
	})
}

func TestFileIamRepository_GetUserWithRoles(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	// Create user
	params := CreateUserParams{
		Email: "user@example.com",
		Name:  "User With Roles",
	}
	user, err := repo.CreateUser(ctx, params)
	require.NoError(t, err)

	// Create roles
	roleID1, err := repo.CreateRole(ctx, "admin")
	require.NoError(t, err)
	roleID2, err := repo.CreateRole(ctx, "editor")
	require.NoError(t, err)

	// Assign roles to user
	err = repo.CreateUserRole(ctx, UserRoleParams{UserID: user.ID, RoleID: roleID1})
	require.NoError(t, err)
	err = repo.CreateUserRole(ctx, UserRoleParams{UserID: user.ID, RoleID: roleID2})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		userWithRoles, err := repo.GetUserWithRoles(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, userWithRoles.ID)
		assert.Len(t, userWithRoles.Roles, 2)

		roleNames := make([]string, len(userWithRoles.Roles))
		for i, role := range userWithRoles.Roles {
			roleNames[i] = role.Name
		}
		assert.Contains(t, roleNames, "admin")
		assert.Contains(t, roleNames, "editor")
	})

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.GetUserWithRoles(ctx, uuid.New())
		assert.Error(t, err)
	})
}

func TestFileIamRepository_FindUsersWithRoles(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	// Create users
	user1, err := repo.CreateUser(ctx, CreateUserParams{Email: "user1@example.com"})
	require.NoError(t, err)
	user2, err := repo.CreateUser(ctx, CreateUserParams{Email: "user2@example.com"})
	require.NoError(t, err)

	// Create role and assign
	roleID, err := repo.CreateRole(ctx, "viewer")
	require.NoError(t, err)
	err = repo.CreateUserRole(ctx, UserRoleParams{UserID: user1.ID, RoleID: roleID})
	require.NoError(t, err)

	t.Run("FindAll", func(t *testing.T) {
		users, err := repo.FindUsersWithRoles(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(users), 2)

		// Find our test users
		found1, found2 := false, false
		for _, u := range users {
			if u.ID == user1.ID {
				found1 = true
				assert.Len(t, u.Roles, 1)
			}
			if u.ID == user2.ID {
				found2 = true
				assert.Empty(t, u.Roles)
			}
		}
		assert.True(t, found1 && found2)
	})
}

func TestFileIamRepository_UpdateUser(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	// Create user
	user, err := repo.CreateUser(ctx, CreateUserParams{
		Email: "original@example.com",
		Name:  "Original Name",
	})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		newLoginID := uuid.New()
		params := UpdateUserParams{
			ID:      user.ID,
			Email:   "updated@example.com",
			Name:    "Updated Name",
			LoginID: &newLoginID,
		}

		updatedUser, err := repo.UpdateUser(ctx, params)
		require.NoError(t, err)
		assert.Equal(t, params.Email, updatedUser.Email)
		assert.Equal(t, params.Name, updatedUser.Name)
		assert.NotNil(t, updatedUser.LoginID)
		assert.Equal(t, newLoginID, *updatedUser.LoginID)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		_, err := repo.UpdateUser(ctx, UpdateUserParams{
			ID:    uuid.New(),
			Email: "test@example.com",
		})
		assert.Error(t, err)
	})
}

func TestFileIamRepository_UpdateUserLoginID(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := repo.CreateUser(ctx, CreateUserParams{Email: "test@example.com"})
	require.NoError(t, err)

	t.Run("SetLoginID", func(t *testing.T) {
		loginID := uuid.New()
		updatedUser, err := repo.UpdateUserLoginID(ctx, user.ID, &loginID)
		require.NoError(t, err)
		assert.NotNil(t, updatedUser.LoginID)
		assert.Equal(t, loginID, *updatedUser.LoginID)
	})

	t.Run("ClearLoginID", func(t *testing.T) {
		updatedUser, err := repo.UpdateUserLoginID(ctx, user.ID, nil)
		require.NoError(t, err)
		assert.Nil(t, updatedUser.LoginID)
	})
}

func TestFileIamRepository_DeleteUser(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := repo.CreateUser(ctx, CreateUserParams{Email: "delete@example.com"})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.DeleteUser(ctx, user.ID)
		require.NoError(t, err)

		// User should still exist but have DeletedAt set
		deletedUser, exists := repo.data.Users[user.ID]
		assert.True(t, exists)
		assert.NotNil(t, deletedUser.DeletedAt)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		err := repo.DeleteUser(ctx, uuid.New())
		assert.Error(t, err)
	})
}

func TestFileIamRepository_DeleteUserRoles(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := repo.CreateUser(ctx, CreateUserParams{Email: "test@example.com"})
	require.NoError(t, err)

	roleID, err := repo.CreateRole(ctx, "admin")
	require.NoError(t, err)

	err = repo.CreateUserRole(ctx, UserRoleParams{UserID: user.ID, RoleID: roleID})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.DeleteUserRoles(ctx, user.ID)
		require.NoError(t, err)

		// User should have no roles
		userWithRoles, err := repo.GetUserWithRoles(ctx, user.ID)
		require.NoError(t, err)
		assert.Empty(t, userWithRoles.Roles)
	})
}

func TestFileIamRepository_AnyUserExists(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	t.Run("NoUsers", func(t *testing.T) {
		exists, err := repo.AnyUserExists(ctx)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("UserExists", func(t *testing.T) {
		_, err := repo.CreateUser(ctx, CreateUserParams{Email: "exists@example.com"})
		require.NoError(t, err)

		exists, err := repo.AnyUserExists(ctx)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("OnlyDeletedUsers", func(t *testing.T) {
		repo2, _, _ := setupTestRepos(t)
		user, err := repo2.CreateUser(ctx, CreateUserParams{Email: "deleted@example.com"})
		require.NoError(t, err)
		err = repo2.DeleteUser(ctx, user.ID)
		require.NoError(t, err)

		exists, err := repo2.AnyUserExists(ctx)
		require.NoError(t, err)
		assert.False(t, exists) // Deleted users don't count
	})
}

func TestFileIamRepository_CreateUserRole(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := repo.CreateUser(ctx, CreateUserParams{Email: "test@example.com"})
	require.NoError(t, err)

	roleID, err := repo.CreateRole(ctx, "admin")
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := repo.CreateUserRole(ctx, UserRoleParams{
			UserID: user.ID,
			RoleID: roleID,
		})
		require.NoError(t, err)

		// Verify role was assigned
		userWithRoles, err := repo.GetUserWithRoles(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, userWithRoles.Roles, 1)
		assert.Equal(t, roleID, userWithRoles.Roles[0].ID)
	})

	t.Run("DuplicateAssignment", func(t *testing.T) {
		// Assigning same role twice should not error
		err := repo.CreateUserRole(ctx, UserRoleParams{
			UserID: user.ID,
			RoleID: roleID,
		})
		require.NoError(t, err)

		// Should still only have one role
		userWithRoles, err := repo.GetUserWithRoles(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, userWithRoles.Roles, 1)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		err := repo.CreateUserRole(ctx, UserRoleParams{
			UserID: uuid.New(),
			RoleID: roleID,
		})
		assert.Error(t, err)
	})

	t.Run("RoleNotFound", func(t *testing.T) {
		err := repo.CreateUserRole(ctx, UserRoleParams{
			UserID: user.ID,
			RoleID: uuid.New(),
		})
		assert.Error(t, err)
	})
}

func TestFileIamRepository_FindRoles(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	_, err := repo.CreateRole(ctx, "admin")
	require.NoError(t, err)
	_, err = repo.CreateRole(ctx, "editor")
	require.NoError(t, err)

	t.Run("FindAll", func(t *testing.T) {
		roles, err := repo.FindRoles(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(roles), 2)

		roleNames := make([]string, len(roles))
		for i, role := range roles {
			roleNames[i] = role.Name
		}
		assert.Contains(t, roleNames, "admin")
		assert.Contains(t, roleNames, "editor")
	})
}

func TestFileIamRepository_CreateRole(t *testing.T) {
	repo, _, _ := setupTestRepos(t)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		roleID, err := repo.CreateRole(ctx, "moderator")
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, roleID)

		// Verify role exists
		roles, err := repo.FindRoles(ctx)
		require.NoError(t, err)

		found := false
		for _, role := range roles {
			if role.ID == roleID {
				found = true
				assert.Equal(t, "moderator", role.Name)
			}
		}
		assert.True(t, found)
	})
}

// ========== IamGroupRepository Tests ==========

func TestFileIamGroupRepository_CreateGroup(t *testing.T) {
	_, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		params := CreateGroupParams{
			Name:        "Developers",
			Description: "Development team",
		}

		group, err := groupRepo.CreateGroup(ctx, params)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, group.ID)
		assert.Equal(t, params.Name, group.Name)
		assert.Equal(t, params.Description, group.Description)
		assert.Nil(t, group.DeletedAt)
	})
}

func TestFileIamGroupRepository_GetGroup(t *testing.T) {
	_, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "Admins"})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		foundGroup, err := groupRepo.GetGroup(ctx, group.ID)
		require.NoError(t, err)
		assert.Equal(t, group.ID, foundGroup.ID)
		assert.Equal(t, group.Name, foundGroup.Name)
	})

	t.Run("GroupNotFound", func(t *testing.T) {
		_, err := groupRepo.GetGroup(ctx, uuid.New())
		assert.Error(t, err)
	})
}

func TestFileIamGroupRepository_FindGroups(t *testing.T) {
	_, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	group1, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "Group1"})
	require.NoError(t, err)
	_, err = groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "Group2"})
	require.NoError(t, err)

	// Delete one group
	err = groupRepo.DeleteGroup(ctx, group1.ID)
	require.NoError(t, err)

	t.Run("OnlyNonDeleted", func(t *testing.T) {
		groups, err := groupRepo.FindGroups(ctx)
		require.NoError(t, err)

		// Should not include deleted group
		for _, g := range groups {
			assert.NotEqual(t, group1.ID, g.ID)
		}
	})
}

func TestFileIamGroupRepository_UpdateGroup(t *testing.T) {
	_, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{
		Name:        "Original",
		Description: "Original Description",
	})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		params := UpdateGroupParams{
			ID:          group.ID,
			Name:        "Updated",
			Description: "Updated Description",
		}

		updatedGroup, err := groupRepo.UpdateGroup(ctx, params)
		require.NoError(t, err)
		assert.Equal(t, params.Name, updatedGroup.Name)
		assert.Equal(t, params.Description, updatedGroup.Description)
	})

	t.Run("GroupNotFound", func(t *testing.T) {
		_, err := groupRepo.UpdateGroup(ctx, UpdateGroupParams{
			ID:   uuid.New(),
			Name: "Nonexistent",
		})
		assert.Error(t, err)
	})
}

func TestFileIamGroupRepository_DeleteGroup(t *testing.T) {
	_, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "ToDelete"})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := groupRepo.DeleteGroup(ctx, group.ID)
		require.NoError(t, err)

		// Group should still exist but have DeletedAt set
		foundGroup, err := groupRepo.GetGroup(ctx, group.ID)
		require.NoError(t, err)
		assert.NotNil(t, foundGroup.DeletedAt)
	})
}

func TestFileIamGroupRepository_FindGroupUsers(t *testing.T) {
	iamRepo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	// Create group and users
	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "Team"})
	require.NoError(t, err)

	user1, err := iamRepo.CreateUser(ctx, CreateUserParams{Email: "user1@example.com"})
	require.NoError(t, err)
	user2, err := iamRepo.CreateUser(ctx, CreateUserParams{Email: "user2@example.com"})
	require.NoError(t, err)
	deletedUser, err := iamRepo.CreateUser(ctx, CreateUserParams{Email: "deleted@example.com"})
	require.NoError(t, err)

	// Assign users to group
	err = groupRepo.CreateUserGroup(ctx, UserGroupParams{UserID: user1.ID, GroupID: group.ID})
	require.NoError(t, err)
	err = groupRepo.CreateUserGroup(ctx, UserGroupParams{UserID: user2.ID, GroupID: group.ID})
	require.NoError(t, err)
	err = groupRepo.CreateUserGroup(ctx, UserGroupParams{UserID: deletedUser.ID, GroupID: group.ID})
	require.NoError(t, err)

	// Delete one user
	err = iamRepo.DeleteUser(ctx, deletedUser.ID)
	require.NoError(t, err)

	t.Run("ExcludesDeletedUsers", func(t *testing.T) {
		users, err := groupRepo.FindGroupUsers(ctx, group.ID)
		require.NoError(t, err)
		assert.Len(t, users, 2) // Should not include deleted user

		userIDs := make([]uuid.UUID, len(users))
		for i, u := range users {
			userIDs[i] = u.ID
		}
		assert.Contains(t, userIDs, user1.ID)
		assert.Contains(t, userIDs, user2.ID)
		assert.NotContains(t, userIDs, deletedUser.ID)
	})
}

func TestFileIamGroupRepository_CreateUserGroup(t *testing.T) {
	iamRepo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := iamRepo.CreateUser(ctx, CreateUserParams{Email: "test@example.com"})
	require.NoError(t, err)

	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "TestGroup"})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := groupRepo.CreateUserGroup(ctx, UserGroupParams{
			UserID:  user.ID,
			GroupID: group.ID,
		})
		require.NoError(t, err)

		// Verify user is in group
		users, err := groupRepo.FindGroupUsers(ctx, group.ID)
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, user.ID, users[0].ID)
	})

	t.Run("DuplicateAssignment", func(t *testing.T) {
		// Assigning same user to same group twice should not error
		err := groupRepo.CreateUserGroup(ctx, UserGroupParams{
			UserID:  user.ID,
			GroupID: group.ID,
		})
		require.NoError(t, err)

		// Should still only have one user
		users, err := groupRepo.FindGroupUsers(ctx, group.ID)
		require.NoError(t, err)
		assert.Len(t, users, 1)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		err := groupRepo.CreateUserGroup(ctx, UserGroupParams{
			UserID:  uuid.New(),
			GroupID: group.ID,
		})
		assert.Error(t, err)
	})

	t.Run("GroupNotFound", func(t *testing.T) {
		err := groupRepo.CreateUserGroup(ctx, UserGroupParams{
			UserID:  user.ID,
			GroupID: uuid.New(),
		})
		assert.Error(t, err)
	})
}

func TestFileIamGroupRepository_UpsertUserGroup(t *testing.T) {
	iamRepo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := iamRepo.CreateUser(ctx, CreateUserParams{Email: "test@example.com"})
	require.NoError(t, err)

	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "TestGroup"})
	require.NoError(t, err)

	t.Run("SameAsCreateUserGroup", func(t *testing.T) {
		err := groupRepo.UpsertUserGroup(ctx, UserGroupParams{
			UserID:  user.ID,
			GroupID: group.ID,
		})
		require.NoError(t, err)

		users, err := groupRepo.FindGroupUsers(ctx, group.ID)
		require.NoError(t, err)
		assert.Len(t, users, 1)
	})
}

func TestFileIamGroupRepository_DeleteUserGroup(t *testing.T) {
	iamRepo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	user, err := iamRepo.CreateUser(ctx, CreateUserParams{Email: "test@example.com"})
	require.NoError(t, err)

	group, err := groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "TestGroup"})
	require.NoError(t, err)

	err = groupRepo.CreateUserGroup(ctx, UserGroupParams{
		UserID:  user.ID,
		GroupID: group.ID,
	})
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		err := groupRepo.DeleteUserGroup(ctx, user.ID, group.ID)
		require.NoError(t, err)

		// User should no longer be in group
		users, err := groupRepo.FindGroupUsers(ctx, group.ID)
		require.NoError(t, err)
		assert.Empty(t, users)
	})
}

// ========== Persistence and Concurrency Tests ==========

func TestFileIamRepository_Persistence(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "iam-test-persist-"+uuid.New().String())
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// Create repository and add data
	repo1, err := NewFileIamRepository(tempDir)
	require.NoError(t, err)

	user, err := repo1.CreateUser(ctx, CreateUserParams{Email: "persist@example.com"})
	require.NoError(t, err)

	roleID, err := repo1.CreateRole(ctx, "admin")
	require.NoError(t, err)

	err = repo1.CreateUserRole(ctx, UserRoleParams{UserID: user.ID, RoleID: roleID})
	require.NoError(t, err)

	groupRepo1 := NewFileIamGroupRepository(repo1)
	group, err := groupRepo1.CreateGroup(ctx, CreateGroupParams{Name: "PersistGroup"})
	require.NoError(t, err)

	err = groupRepo1.CreateUserGroup(ctx, UserGroupParams{UserID: user.ID, GroupID: group.ID})
	require.NoError(t, err)

	// Create new repository from same directory (simulating restart)
	repo2, err := NewFileIamRepository(tempDir)
	require.NoError(t, err)

	// Data should be loaded
	userWithRoles, err := repo2.GetUserWithRoles(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, userWithRoles.Email)
	assert.Len(t, userWithRoles.Roles, 1)
	assert.Equal(t, "admin", userWithRoles.Roles[0].Name)

	groupRepo2 := NewFileIamGroupRepository(repo2)
	foundGroup, err := groupRepo2.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "PersistGroup", foundGroup.Name)

	users, err := groupRepo2.FindGroupUsers(ctx, group.ID)
	require.NoError(t, err)
	assert.Len(t, users, 1)
}

func TestFileIamRepository_ConcurrentAccess(t *testing.T) {
	repo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	numGoroutines := 50
	var wg sync.WaitGroup

	t.Run("ConcurrentUserCreates", func(t *testing.T) {
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				_, _ = repo.CreateUser(ctx, CreateUserParams{
					Email: "concurrent" + string(rune(index)) + "@example.com",
				})
			}(i)
		}
		wg.Wait()

		users, err := repo.FindUsersWithRoles(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(users), numGoroutines)
	})

	t.Run("ConcurrentGroupCreates", func(t *testing.T) {
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(index int) {
				defer wg.Done()
				_, _ = groupRepo.CreateGroup(ctx, CreateGroupParams{
					Name: "Group" + string(rune(index)),
				})
			}(i)
		}
		wg.Wait()

		groups, err := groupRepo.FindGroups(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(groups), numGoroutines)
	})

	t.Run("MixedConcurrentAccess", func(t *testing.T) {
		user, err := repo.CreateUser(ctx, CreateUserParams{Email: "mixed@example.com"})
		require.NoError(t, err)

		roleID, err := repo.CreateRole(ctx, "viewer")
		require.NoError(t, err)

		wg.Add(numGoroutines * 2)

		// Concurrent role assignments
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_ = repo.CreateUserRole(ctx, UserRoleParams{
					UserID: user.ID,
					RoleID: roleID,
				})
			}()
		}

		// Concurrent reads
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_, _ = repo.GetUserWithRoles(ctx, user.ID)
			}()
		}

		wg.Wait()

		// Verify final state
		userWithRoles, err := repo.GetUserWithRoles(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, userWithRoles.Roles, 1)
	})
}

func TestFileIamRepository_SaveLoad(t *testing.T) {
	repo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	// Add multiple users, roles, and groups
	for i := 0; i < 3; i++ {
		_, _ = repo.CreateUser(ctx, CreateUserParams{Email: "user@example.com"})
		_, _ = repo.CreateRole(ctx, "role")
		_, _ = groupRepo.CreateGroup(ctx, CreateGroupParams{Name: "group"})
	}

	initialUserCount := len(repo.data.Users)
	initialRoleCount := len(repo.data.Roles)
	initialGroupCount := len(repo.data.Groups)

	// Save
	repo.mutex.Lock()
	err := repo.save()
	repo.mutex.Unlock()
	require.NoError(t, err)

	// Clear and reload
	repo.mutex.Lock()
	repo.data = &fileIamData{
		Users:      make(map[uuid.UUID]User),
		Roles:      make(map[uuid.UUID]Role),
		UserRoles:  make(map[uuid.UUID][]uuid.UUID),
		Groups:     make(map[uuid.UUID]Group),
		UserGroups: make(map[uuid.UUID][]uuid.UUID),
	}
	err = repo.load()
	repo.mutex.Unlock()
	require.NoError(t, err)

	assert.Equal(t, initialUserCount, len(repo.data.Users))
	assert.Equal(t, initialRoleCount, len(repo.data.Roles))
	assert.Equal(t, initialGroupCount, len(repo.data.Groups))
}

func TestFileIamRepository_EmptyData(t *testing.T) {
	repo, groupRepo, _ := setupTestRepos(t)
	ctx := context.Background()

	// Empty repository operations should return appropriate errors/empty results
	_, err := repo.GetUserWithRoles(ctx, uuid.New())
	assert.Error(t, err)

	users, err := repo.FindUsersWithRoles(ctx)
	require.NoError(t, err)
	assert.Empty(t, users)

	roles, err := repo.FindRoles(ctx)
	require.NoError(t, err)
	assert.Empty(t, roles)

	exists, err := repo.AnyUserExists(ctx)
	require.NoError(t, err)
	assert.False(t, exists)

	_, err = groupRepo.GetGroup(ctx, uuid.New())
	assert.Error(t, err)

	groups, err := groupRepo.FindGroups(ctx)
	require.NoError(t, err)
	assert.Empty(t, groups)
}
