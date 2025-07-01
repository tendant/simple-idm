package profile

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/exp/slog"
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

func TestUpdateUsername(t *testing.T) {
	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create repository and service
	queries := profiledb.New(pool)
	repository := NewPostgresProfileRepository(queries)
	// Create a mock user mapper and notification manager for testing
	service := NewProfileService(repository, nil, nil, nil)

	// Create a test user with a known password
	ctx := context.Background()
	password := "testpass"
	// Create a temporary password manager for hashing
	tempPasswordManager := login.NewPasswordManager(nil)
	hashedPassword, err := tempPasswordManager.HashPassword(password)
	require.NoError(t, err)

	// Create test user directly in database
	userUUID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO users (uuid, username, email, password, created_at, last_modified_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, userUUID, "oldusername", "test@example.com", []byte(hashedPassword))
	require.NoError(t, err)

	// Create another user for testing username conflicts
	conflictUserUUID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO users (uuid, username, email, password, created_at, last_modified_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, conflictUserUUID, "existinguser", "existing@example.com", []byte(hashedPassword))
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name          string
		params        UpdateUsernameParams
		expectedError string
	}{
		{
			name: "successful username update",
			params: UpdateUsernameParams{
				LoginID:         userUUID,
				CurrentPassword: password,
				NewUsername:     "newusername",
			},
			expectedError: "",
		},
		{
			name: "invalid current password",
			params: UpdateUsernameParams{
				LoginID:         userUUID,
				CurrentPassword: "wrongpass",
				NewUsername:     "newusername2",
			},
			expectedError: "invalid current password",
		},
		{
			name: "username already taken",
			params: UpdateUsernameParams{
				LoginID:         userUUID,
				CurrentPassword: password,
				NewUsername:     "existinguser",
			},
			expectedError: "username already taken",
		},
		{
			name: "user not found",
			params: UpdateUsernameParams{
				LoginID:         uuid.New(), // Different UUID
				CurrentPassword: password,
				NewUsername:     "newusername3",
			},
			expectedError: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the method
			err := service.UpdateUsername(ctx, tt.params)

			// Check error
			if tt.expectedError != "" {
				require.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)

				// Verify username was actually updated
				var storedUsername string
				err = pool.QueryRow(ctx, "SELECT username FROM users WHERE uuid = $1", tt.params.LoginID).Scan(&storedUsername)
				require.NoError(t, err)
				require.Equal(t, tt.params.NewUsername, storedUsername, "New username should be stored in database")
			}
		})
	}
}

func TestUpdatePassword(t *testing.T) {
	// Setup test database
	pool, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create repository and service
	queries := profiledb.New(pool)
	repository := NewPostgresProfileRepository(queries)
	// Create a mock user mapper and notification manager for testing
	service := NewProfileService(repository, nil, nil, nil)

	// Create a test user with a known password
	ctx := context.Background()
	initialPassword := "oldpass"
	// Create a temporary password manager for hashing
	tempPasswordManager := login.NewPasswordManager(nil)
	hashedPassword, err := tempPasswordManager.HashPassword(initialPassword)
	require.NoError(t, err)

	// Create test user directly in database
	userUUID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO users (uuid, email, password, created_at, last_modified_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, userUUID, "test@example.com", []byte(hashedPassword))
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name          string
		params        UpdatePasswordParams
		expectedError string
	}{
		{
			name: "successful password update",
			params: UpdatePasswordParams{
				LoginID:         userUUID,
				CurrentPassword: initialPassword,
				NewPassword:     "newpass",
			},
			expectedError: "",
		},
		{
			name: "invalid current password",
			params: UpdatePasswordParams{
				LoginID:         userUUID,
				CurrentPassword: "wrongpass",
				NewPassword:     "newpass",
			},
			expectedError: "invalid current password",
		},
		{
			name: "user not found",
			params: UpdatePasswordParams{
				LoginID:         uuid.New(), // Different UUID
				CurrentPassword: initialPassword,
				NewPassword:     "newpass",
			},
			expectedError: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the method
			err := service.UpdatePassword(ctx, tt.params)

			// Check error
			if tt.expectedError != "" {
				require.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)

				// Verify password was actually updated
				var storedPassword []byte
				err = pool.QueryRow(ctx, "SELECT password FROM users WHERE uuid = $1", tt.params.LoginID).Scan(&storedPassword)
				require.NoError(t, err)

				// Verify new password works
				tempPasswordManager := login.NewPasswordManager(nil)
				match, err := tempPasswordManager.CheckPasswordHash(tt.params.NewPassword, string(storedPassword), login.PasswordV1)
				require.NoError(t, err)
				require.True(t, match, "New password should match stored hash")
			}
		})
	}
}
