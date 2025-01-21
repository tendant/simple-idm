package user

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/user/db"
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

func TestCreateUser(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := db.New(pool)
	service := NewUserService(queries)

	// Create a test role first
	roleUUID := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (uuid, name, description)
		VALUES ($1, $2, $3)
	`, roleUUID, "TestRole", "A test role")
	require.NoError(t, err)

	testCases := []struct {
		name      string
		email     string
		username  string
		fullname  string
		roleUuids []uuid.UUID
		wantErr   bool
	}{
		{
			name:      "successful creation",
			email:     "test@example.com",
			username:  "testuser",
			fullname:  "Test User",
			roleUuids: []uuid.UUID{roleUUID},
			wantErr:   false,
		},
		{
			name:      "empty email",
			email:     "",
			username:  "testuser",
			fullname:  "Test User",
			roleUuids: []uuid.UUID{roleUUID},
			wantErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute test
			user, err := service.CreateUser(ctx, tc.email, tc.username, tc.fullname, tc.roleUuids)

			// Verify results
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.email, user.Email)
			assert.Equal(t, tc.username, user.Username.String)
			assert.Equal(t, tc.fullname, user.Name.String)
			assert.True(t, user.Username.Valid)
			assert.True(t, user.Name.Valid)

			// Verify the user exists in the database
			var dbUser db.User
			err = pool.QueryRow(ctx, `
				SELECT uuid, email, username, name
				FROM users
				WHERE uuid = $1
			`, user.Uuid).Scan(&dbUser.Uuid, &dbUser.Email, &dbUser.Username, &dbUser.Name)
			assert.NoError(t, err)
			assert.Equal(t, tc.email, dbUser.Email)
			assert.Equal(t, tc.username, dbUser.Username.String)
			assert.Equal(t, tc.fullname, dbUser.Name.String)

			// Verify the role assignment
			var roleCount int
			err = pool.QueryRow(ctx, `
				SELECT COUNT(*)
				FROM user_roles
				WHERE user_uuid = $1 AND role_uuid = $2
			`, user.Uuid, tc.roleUuids[0]).Scan(&roleCount)
			assert.NoError(t, err)
			assert.Equal(t, 1, roleCount)
		})
	}
}

func TestFindUsers(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := db.New(pool)
	service := NewUserService(queries)

	// Create test roles
	role1UUID := uuid.New()
	role2UUID := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (uuid, name, description)
		VALUES ($1, $2, $3), ($4, $5, $6)
	`, role1UUID, "TestRole1", "A test role 1",
		role2UUID, "TestRole2", "A test role 2")
	require.NoError(t, err)

	// Create test users with roles
	testUsers := []struct {
		email     string
		username  string
		name      string
		roleUuids []uuid.UUID
	}{
		{
			email:     "user1@example.com",
			username:  "user1",
			name:      "User One",
			roleUuids: []uuid.UUID{role1UUID},
		},
		{
			email:     "user2@example.com",
			username:  "user2",
			name:      "User Two",
			roleUuids: []uuid.UUID{role1UUID, role2UUID},
		},
	}

	for _, u := range testUsers {
		_, err := service.CreateUser(ctx, u.email, u.username, u.name, u.roleUuids)
		require.NoError(t, err)
	}

	// Test FindUsers
	users, err := service.FindUsers(ctx)
	require.NoError(t, err)
	assert.Len(t, users, 2)

	// Create a map of users by email for easier verification
	userMap := make(map[string]db.FindUsersWithRolesRow)
	for _, u := range users {
		userMap[u.Email] = u
	}

	// Verify user details
	user1 := userMap["user1@example.com"]
	assert.Equal(t, "User One", user1.Name.String)

	user2 := userMap["user2@example.com"]
	assert.Equal(t, "User Two", user2.Name.String)
}

func TestGetUser(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := db.New(pool)
	service := NewUserService(queries)

	// Create a test role
	roleUUID := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (uuid, name, description)
		VALUES ($1, $2, $3)
	`, roleUUID, "TestRole", "A test role")
	require.NoError(t, err)

	// Create a test user
	user, err := service.CreateUser(ctx, "test@example.com", "testuser", "Test User", []uuid.UUID{roleUUID})
	require.NoError(t, err)

	// Test cases
	t.Run("existing user", func(t *testing.T) {
		// Get the user
		fetchedUser, err := service.GetUser(ctx, user.Uuid)
		require.NoError(t, err)
		assert.Equal(t, user.Email, fetchedUser.Email)
		assert.Equal(t, user.Name, fetchedUser.Name)
	})

	t.Run("non-existent user", func(t *testing.T) {
		// Try to get a non-existent user
		_, err := service.GetUser(ctx, uuid.New())
		assert.Error(t, err)
	})
}

func TestUpdateUser(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := db.New(pool)
	service := NewUserService(queries)

	// Create test roles
	role1UUID := uuid.New()
	role2UUID := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (uuid, name, description)
		VALUES ($1, $2, $3), ($4, $5, $6)
	`, role1UUID, "TestRole1", "A test role 1",
		role2UUID, "TestRole2", "A test role 2")
	require.NoError(t, err)

	// Create a test user with role1
	user, err := service.CreateUser(ctx, "test@example.com", "testuser", "Original Name", []uuid.UUID{role1UUID})
	require.NoError(t, err)

	// Test cases
	t.Run("update name and roles", func(t *testing.T) {
		// Update user's name and roles
		updatedUser, err := service.UpdateUser(ctx, user.Uuid, "Updated Name", []uuid.UUID{role2UUID})
		require.NoError(t, err)

		// Verify updated user
		assert.Equal(t, "Updated Name", updatedUser.Name.String)
		assert.Equal(t, user.Email, updatedUser.Email)

		// Verify roles were updated
		var roleCount int
		err = pool.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM user_roles
			WHERE user_uuid = $1 AND role_uuid = $2
		`, user.Uuid, role2UUID).Scan(&roleCount)
		assert.NoError(t, err)
		assert.Equal(t, 1, roleCount)

		// Verify old role was removed
		err = pool.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM user_roles
			WHERE user_uuid = $1 AND role_uuid = $2
		`, user.Uuid, role1UUID).Scan(&roleCount)
		assert.NoError(t, err)
		assert.Equal(t, 0, roleCount)
	})

	t.Run("non-existent user", func(t *testing.T) {
		// Try to update a non-existent user
		_, err := service.UpdateUser(ctx, uuid.New(), "New Name", []uuid.UUID{role1UUID})
		assert.Error(t, err)
	})
}

func TestDeleteUser(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create test dependencies
	queries := db.New(pool)
	service := NewUserService(queries)

	// Create a test role
	roleUUID := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (uuid, name, description)
		VALUES ($1, $2, $3)
	`, roleUUID, "TestRole", "A test role")
	require.NoError(t, err)

	// Create a test user
	user, err := service.CreateUser(ctx, "test@example.com", "testuser", "Test User", []uuid.UUID{roleUUID})
	require.NoError(t, err)

	// Test cases
	t.Run("existing user", func(t *testing.T) {
		// Delete the user
		err := service.DeleteUser(ctx, user.Uuid)
		require.NoError(t, err)

		// Verify user is marked as deleted
		var deletedAt sql.NullTime
		err = pool.QueryRow(ctx, `
			SELECT deleted_at
			FROM users
			WHERE uuid = $1
		`, user.Uuid).Scan(&deletedAt)
		assert.NoError(t, err)
		assert.True(t, deletedAt.Valid)
	})

	t.Run("non-existent user", func(t *testing.T) {
		// Try to delete a non-existent user
		err := service.DeleteUser(ctx, uuid.New())
		assert.Error(t, err)
	})
}
