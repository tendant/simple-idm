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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/role/roledb"
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

func TestCreateRole(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := roledb.New(pool)
	service := NewRoleService(queries)

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

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := roledb.New(pool)
	service := NewRoleService(queries)

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

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := roledb.New(pool)
	service := NewRoleService(queries)

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

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := roledb.New(pool)
	service := NewRoleService(queries)

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

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := roledb.New(pool)
	service := NewRoleService(queries)

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
