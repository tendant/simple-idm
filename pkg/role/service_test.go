package role

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func containerLog(ctx context.Context, container testcontainers.Container) {
	// Retrieve logs
	logs, err := container.Logs(ctx)
	if err != nil {
		slog.Error("Failed to get container logs:", "err", err)
	}
	defer logs.Close()

	// Process and display logs
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		fmt.Println(scanner.Text()) // Print each log line
	}

	// Check for scanning errors
	if err := scanner.Err(); err != nil {
		slog.Error("Error reading logs", "err", err)
	}
}

func setupTestDatabase(t *testing.T) (*pgxpool.Pool, func()) {
	ctx := context.Background()

	// Create PostgreSQL container
	dbName := "idm_db"
	dbUser := "idm"
	dbPassword := "pwd"

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithInitScripts(filepath.Join("../../migrations", "idm_db.sql")),
		// postgres.WithConfigFile(filepath.Join("testdata", "my-postgres.conf")),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.NoError(t, err)
	if err != nil {
		slog.Error("Failed to start container:", "err", err)
	}

	// containerLog(ctx, container)

	// Generate the connection string
	connString, err := container.ConnectionString(ctx)
	fmt.Println("Connection string:", connString)
	require.NoError(t, err)

	// Create connection pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	require.NoError(t, err)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return pool, cleanup
}

// MockRoleRepository is a mock implementation of the RoleRepository interface for testing
type MockRoleRepository struct {
	roles      []Role
	roleUsers  map[uuid.UUID][]RoleUser
	lastRoleID uuid.UUID
}

// NewMockRoleRepository creates a new mock repository
func NewMockRoleRepository() *MockRoleRepository {
	return &MockRoleRepository{
		roles:     make([]Role, 0),
		roleUsers: make(map[uuid.UUID][]RoleUser),
	}
}

// FindRoles returns all roles
func (m *MockRoleRepository) FindRoles(ctx context.Context) ([]Role, error) {
	return m.roles, nil
}

// CreateRole creates a new role
func (m *MockRoleRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	id := uuid.New()
	m.roles = append(m.roles, Role{ID: id, Name: name})
	m.lastRoleID = id
	return id, nil
}

// UpdateRole updates an existing role
func (m *MockRoleRepository) UpdateRole(ctx context.Context, arg UpdateRoleParams) error {
	for i, role := range m.roles {
		if role.ID == arg.ID {
			m.roles[i].Name = arg.Name
			return nil
		}
	}
	return ErrRoleNotFound
}

// DeleteRole deletes a role
func (m *MockRoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	for i, role := range m.roles {
		if role.ID == id {
			m.roles = append(m.roles[:i], m.roles[i+1:]...)
			return nil
		}
	}
	// Role not found, but DELETE is idempotent so return success
	return nil
}

// GetRoleById retrieves a role by ID
func (m *MockRoleRepository) GetRoleById(ctx context.Context, id uuid.UUID) (Role, error) {
	for _, role := range m.roles {
		if role.ID == id {
			return role, nil
		}
	}
	return Role{}, ErrRoleNotFound
}

// GetRoleIdByName retrieves a role ID by name
func (m *MockRoleRepository) GetRoleIdByName(ctx context.Context, name string) (uuid.UUID, error) {
	for _, role := range m.roles {
		if role.Name == name {
			return role.ID, nil
		}
	}
	return uuid.Nil, ErrRoleNotFound
}

// GetRoleUsers retrieves users assigned to a role
func (m *MockRoleRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]RoleUser, error) {
	users, exists := m.roleUsers[roleID]
	if !exists {
		return []RoleUser{}, nil
	}
	return users, nil
}

// HasUsers checks if a role has users assigned
func (m *MockRoleRepository) HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error) {
	users, exists := m.roleUsers[roleID]
	if !exists {
		return false, nil
	}
	return len(users) > 0, nil
}

// RemoveUserFromRole removes a user from a role
func (m *MockRoleRepository) RemoveUserFromRole(ctx context.Context, arg RemoveUserFromRoleParams) error {
	users, exists := m.roleUsers[arg.RoleID]
	if !exists {
		return nil
	}

	for i, user := range users {
		if user.ID == arg.UserID {
			m.roleUsers[arg.RoleID] = append(users[:i], users[i+1:]...)
			return nil
		}
	}
	return nil
}

// WithTx returns a new repository with the given transaction
func (m *MockRoleRepository) WithTx(tx interface{}) RoleRepository {
	return m
}

// WithPgxTx returns a new repository with the given pgx transaction
func (m *MockRoleRepository) WithPgxTx(tx pgx.Tx) RoleRepository {
	return m
}

func TestCreateRole(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Test cases
	tests := []struct {
		name     string
		roleName string
		wantErr  bool
	}{
		{
			name:     "valid role",
			roleName: "test-role",
			wantErr:  false,
		},
		{
			name:     "empty role name",
			roleName: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleID, err := service.CreateRole(ctx, tt.roleName)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEqual(t, uuid.Nil, roleID)

			// Verify role was created
			role, err := service.GetRole(ctx, roleID)
			require.NoError(t, err)
			assert.Equal(t, tt.roleName, role.Name)
		})
	}
}

func TestFindRoles(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Create test roles (in alphabetical order)
	testRoles := []string{
		"admin",
		"guest",
		"user",
	}

	for _, roleName := range testRoles {
		_, err := service.CreateRole(ctx, roleName)
		require.NoError(t, err)
	}

	// Test finding roles
	roles, err := service.FindRoles(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, roles)
	assert.Len(t, roles, len(testRoles))

	// Verify roles are returned in alphabetical order
	for i, role := range roles {
		assert.Equal(t, testRoles[i], role.Name)
	}
}

func TestUpdateRole(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Create initial role
	roleID, err := service.CreateRole(ctx, "initial-role")
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name    string
		roleID  uuid.UUID
		newName string
		wantErr bool
	}{
		{
			name:    "valid update",
			roleID:  roleID,
			newName: "updated-role",
			wantErr: false,
		},
		{
			name:    "non-existent role",
			roleID:  uuid.New(),
			newName: "test",
			wantErr: true,
		},
		{
			name:    "empty name",
			roleID:  roleID,
			newName: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.UpdateRole(ctx, tt.roleID, tt.newName)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Verify role was updated
			role, err := service.GetRole(ctx, tt.roleID)
			require.NoError(t, err)
			assert.Equal(t, tt.newName, role.Name)
		})
	}
}

func TestGetRole(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Create a test role
	roleName := "test-role"
	roleID, err := service.CreateRole(ctx, roleName)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name    string
		roleID  uuid.UUID
		wantErr bool
	}{
		{
			name:    "existing role",
			roleID:  roleID,
			wantErr: false,
		},
		{
			name:    "non-existent role",
			roleID:  uuid.New(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, err := service.GetRole(ctx, tt.roleID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.roleID, role.ID)
			assert.Equal(t, roleName, role.Name)
		})
	}
}

func TestDeleteRole(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Create a test role
	roleID, err := service.CreateRole(ctx, "test-role")
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name    string
		roleID  uuid.UUID
		wantErr bool
	}{
		{
			name:    "existing role",
			roleID:  roleID,
			wantErr: false,
		},
		{
			name:    "non-existent role",
			roleID:  uuid.New(),
			wantErr: false, // DELETE is idempotent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.DeleteRole(ctx, tt.roleID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Verify role was deleted
			_, err = service.GetRole(ctx, tt.roleID)
			assert.Error(t, err) // Should get error when trying to fetch deleted role
		})
	}
}

// AddUserToRole is a helper method for the MockRoleRepository
func (m *MockRoleRepository) AddUserToRole(ctx context.Context, roleID, userID uuid.UUID, username string) error {
	// Check if role exists
	found := false
	for _, role := range m.roles {
		if role.ID == roleID {
			found = true
			break
		}
	}
	if !found {
		return ErrRoleNotFound
	}

	// Add user to role
	if _, exists := m.roleUsers[roleID]; !exists {
		m.roleUsers[roleID] = make([]RoleUser, 0)
	}

	m.roleUsers[roleID] = append(m.roleUsers[roleID], RoleUser{
		ID:    userID,
		Name:  username,
		Email: username + "@example.com",
		NameValid: true,
	})

	return nil
}

func TestAddUserToRole(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Create a test role
	roleID, err := service.CreateRole(ctx, "test-role")
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name     string
		roleID   uuid.UUID
		userID   uuid.UUID
		username string
		wantErr  bool
	}{
		{
			name:     "valid user addition",
			roleID:   roleID,
			userID:   uuid.New(),
			username: "testuser",
			wantErr:  false,
		},
		{
			name:     "non-existent role",
			roleID:   uuid.New(),
			userID:   uuid.New(),
			username: "testuser2",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.AddUserToRole(ctx, tt.roleID, tt.userID, tt.username)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Verify user was added to role
			users, err := repo.GetRoleUsers(ctx, tt.roleID)
			require.NoError(t, err)
			
			found := false
			for _, user := range users {
				if user.ID == tt.userID {
					assert.Equal(t, tt.username, user.Name)
					assert.Equal(t, tt.username+"@example.com", user.Email)
					assert.True(t, user.NameValid)
					found = true
					break
				}
			}
			assert.True(t, found, "User was not added to role")
		})
	}
}

func TestRemoveUserFromRole(t *testing.T) {
	ctx := context.Background()

	// Create mock repository
	repo := NewMockRoleRepository()
	service := NewRoleService(repo)

	// Create a test role
	roleID, err := service.CreateRole(ctx, "test-role")
	require.NoError(t, err)

	// Add a test user to the role
	userID := uuid.New()
	username := "testuser"
	err = repo.AddUserToRole(ctx, roleID, userID, username)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name    string
		roleID  uuid.UUID
		userID  uuid.UUID
		wantErr bool
	}{
		{
			name:    "valid user removal",
			roleID:  roleID,
			userID:  userID,
			wantErr: false,
		},
		{
			name:    "non-existent role",
			roleID:  uuid.New(),
			userID:  userID,
			wantErr: true,
		},
		{
			name:    "non-existent user",
			roleID:  roleID,
			userID:  uuid.New(),
			wantErr: false, // Removing non-existent user is idempotent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.RemoveUserFromRole(ctx, tt.roleID, tt.userID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// For valid removal, verify user was removed
			if tt.roleID == roleID && tt.userID == userID {
				users, err := repo.GetRoleUsers(ctx, roleID)
				require.NoError(t, err)
				
				for _, user := range users {
					assert.NotEqual(t, userID, user.ID, "User was not removed from role")
				}
			}
		})
	}
}
