package user

import (
	"context"
	"testing"

	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/user/db"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"time"
	"path/filepath"
	"bufio"
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

	containerLog(ctx, container)

	
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
		userName  string
		roleUuids []uuid.UUID
		wantErr   bool
	}{
		{
			name:     "successful creation",
			email:    "test@example.com",
			userName: "Test User",
			roleUuids: []uuid.UUID{
				roleUUID,
			},
			wantErr: false,
		},
		{
			name:     "empty email",
			email:    "",
			userName: "Test User",
			roleUuids: []uuid.UUID{
				roleUUID,
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute test
			user, err := service.CreateUser(ctx, tc.email, tc.userName, tc.roleUuids)

			// Verify results
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.email, user.Email)
			assert.Equal(t, tc.userName, user.Name.String)
			assert.True(t, user.Name.Valid)

			// Verify the user exists in the database
			var dbUser db.User
			err = pool.QueryRow(ctx, `
				SELECT uuid, email, name
				FROM users
				WHERE uuid = $1
			`, user.Uuid).Scan(&dbUser.Uuid, &dbUser.Email, &dbUser.Name)
			assert.NoError(t, err)
			assert.Equal(t, tc.email, dbUser.Email)
			assert.Equal(t, tc.userName, dbUser.Name.String)

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
