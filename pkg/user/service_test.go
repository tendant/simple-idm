package user

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/tendant/simple-idm/pkg/user/db"
)

func setupTestDatabase(t *testing.T) (*pgxpool.Pool, func()) {
	ctx := context.Background()

	// Create PostgreSQL container
	container, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.NoError(t, err)

	// Get connection details
	connString, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	// Create connection pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	require.NoError(t, err)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	require.NoError(t, err)

	// Run migrations
	_, err = pool.Exec(ctx, `
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

		CREATE TABLE IF NOT EXISTS users (
			uuid UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP WITH TIME ZONE,
			created_by TEXT,
			email TEXT NOT NULL,
			name TEXT,
			password TEXT,
			verified_at TIMESTAMP WITH TIME ZONE,
			username TEXT
		);

		CREATE TABLE IF NOT EXISTS roles (
			uuid UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name TEXT NOT NULL,
			description TEXT
		);

		CREATE TABLE IF NOT EXISTS user_roles (
			user_uuid UUID REFERENCES users(uuid),
			role_uuid UUID REFERENCES roles(uuid),
			PRIMARY KEY (user_uuid, role_uuid)
		);
	`)
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
