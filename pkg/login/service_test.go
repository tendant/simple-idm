package login_test

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
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

// setupTestServices sets up all necessary services for testing
func setupTestServices(t *testing.T) (*pgxpool.Pool, *login.LoginService, *logins.LoginsService, login.LoginRepository, func()) {
	// Setup test database
	pool, cleanup := setupTestDatabase(t)

	// Create necessary queries
	loginQueries := logindb.New(pool)
	loginsQueries := loginsdb.New(pool)
	mapperQueries := mapperdb.New(pool)

	// Create repository and services
	repository := login.NewPostgresLoginRepository(loginQueries)
	mapperRepo := mapper.NewPostgresMapperRepository(mapperQueries)
	userMapper := mapper.NewDefaultUserMapper(mapperRepo)
	passwordManager := login.NewPasswordManager(loginQueries)

	// Create logins service for creating login
	loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)
	loginsService := logins.NewLoginsService(loginsRepo, loginQueries, nil)

	// Create login service with all necessary components
	loginService := login.NewLoginServiceWithOptions(
		repository,
		login.WithUserMapper(userMapper),
		login.WithPasswordManager(passwordManager),
	)

	return pool, loginService, loginsService, repository, cleanup
}

func TestCheckPasswordHash(t *testing.T) {
	// Use the setupTestServices to get a properly initialized password manager
	_, _, _, _, cleanup := setupTestServices(t)
	defer cleanup()

	// Create a password manager directly for testing
	passwordManager := login.NewPasswordManager(nil)

	// Test cases
	t.Run("ValidPassword", func(t *testing.T) {
		password := "validPassword123"
		hashedPassword, err := passwordManager.HashPassword(password)
		assert.NoError(t, err)

		match, err := passwordManager.CheckPasswordHash(password, hashedPassword, login.CurrentPasswordVersion)
		assert.NoError(t, err)
		assert.True(t, match, "The password should match the hashed password")
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		password := ""
		hashedPassword := ""

		match, err := passwordManager.CheckPasswordHash(password, hashedPassword, login.CurrentPasswordVersion)
		assert.Error(t, err)
		assert.False(t, match, "Empty password and hash should not match")
	})

	t.Run("EmptyHashedPassword", func(t *testing.T) {
		password := "somePassword"
		hashedPassword := ""

		match, err := passwordManager.CheckPasswordHash(password, hashedPassword, login.CurrentPasswordVersion)
		assert.Error(t, err)
		assert.False(t, match, "A valid password and empty hash should not match")
	})

	t.Run("IncorrectPassword", func(t *testing.T) {
		password := "correctPassword"
		hashedPassword, err := passwordManager.HashPassword(password)
		assert.NoError(t, err)

		incorrectPassword := "incorrectPassword"
		match, err := passwordManager.CheckPasswordHash(incorrectPassword, hashedPassword, login.CurrentPasswordVersion)
		assert.NoError(t, err) // This should be NoError since it's a valid check, just returns false
		assert.False(t, match, "Incorrect password should not match the hashed password")
	})

	t.Run("CorruptedHashedPassword", func(t *testing.T) {
		password := "correctPassword"
		corruptedHash := "invalidHash"

		match, err := passwordManager.CheckPasswordHash(password, corruptedHash, login.CurrentPasswordVersion)
		assert.Error(t, err)
		assert.False(t, match, "Corrupted hashed password should not match")
	})

	t.Run("GeneratedHashNotEmpty", func(t *testing.T) {
		password := "myPassword"
		hashedPassword, err := passwordManager.HashPassword(password)
		assert.NoError(t, err)
		assert.NotEmpty(t, hashedPassword, "Hashed password should not be empty")
	})
}

func TestMagicLinkToken(t *testing.T) {
	// Use the new setup method
	pool, loginService, loginsService, repository, cleanup := setupTestServices(t)
	defer cleanup()

	ctx := context.Background()

	// Create a test user using logins service
	username := "testuser@example.com"
	password := "TestPass123!"

	loginModel, err := loginsService.CreateLogin(ctx, logins.LoginCreateRequest{
		Username: username,
		Password: password,
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, loginModel)

	// Parse the login ID
	loginID, err := uuid.Parse(loginModel.ID)
	require.NoError(t, err)

	// Create a user record associated with the login
	userID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO users (id, login_id, email, created_at, last_modified_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, userID, loginID, username)
	require.NoError(t, err)

	t.Run("GenerateMagicLinkToken", func(t *testing.T) {
		// Generate a magic link token
		token, email, err := loginService.GenerateMagicLinkToken(ctx, username)
		require.NoError(t, err)
		require.NotEmpty(t, token, "Token should not be empty")
		require.Equal(t, username, email, "Email should match the user's email")

		// Validate the token using repository method
		retrievedLoginID, err := repository.ValidateMagicLinkToken(ctx, token)
		require.NoError(t, err)
		require.Equal(t, loginID, retrievedLoginID, "Login ID should match")
	})

	t.Run("ValidateMagicLinkToken", func(t *testing.T) {
		// Generate a token using repository method
		token := "valid_token_123"
		expireAt := time.Now().Add(15 * time.Minute)

		err := repository.GenerateMagicLinkToken(ctx, loginID, token, expireAt)
		require.NoError(t, err)

		// Validate the token using service method
		result, err := loginService.ValidateMagicLinkToken(ctx, token)
		require.NoError(t, err)
		require.True(t, result.Success, "Token validation should succeed")
		require.Equal(t, loginID, result.LoginID, "Login ID should match")
		require.NotEmpty(t, result.Users, "Users should not be empty")

		// Try to validate the token again - should fail because it's been used
		_, err = loginService.ValidateMagicLinkToken(ctx, token)
		require.Error(t, err, "Used token should not validate")
		require.Contains(t, err.Error(), "invalid or expired token", "Error should mention token is invalid")
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		// Generate an expired token using repository method
		token := "expired_token_123"
		expireAt := time.Now().Add(-15 * time.Minute) // Expired 15 minutes ago

		err := repository.GenerateMagicLinkToken(ctx, loginID, token, expireAt)
		require.NoError(t, err)

		// Try to validate the expired token
		_, err = loginService.ValidateMagicLinkToken(ctx, token)
		require.Error(t, err, "Expired token should not validate")
		require.Contains(t, err.Error(), "invalid or expired token", "Error should mention token is expired")
	})
}

func TestPasswordlessLogin(t *testing.T) {
	// Use the new setup method
	_, _, loginsService, repository, cleanup := setupTestServices(t)
	defer cleanup()

	ctx := context.Background()

	// Create a test user using logins service
	username := "passwordless@example.com"
	password := "TestPass123!"

	loginModel, err := loginsService.CreateLogin(ctx, logins.LoginCreateRequest{
		Username: username,
		Password: password,
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, loginModel)

	// Parse the login ID
	loginID, err := uuid.Parse(loginModel.ID)
	require.NoError(t, err)

	t.Run("SetPasswordlessFlag", func(t *testing.T) {
		// Set the passwordless flag
		err := repository.SetPasswordlessFlag(ctx, loginID, true)
		require.NoError(t, err)

		// Verify flag is set
		isPasswordless, err := repository.IsPasswordlessLogin(ctx, loginID)
		require.NoError(t, err)
		require.True(t, isPasswordless, "Passwordless flag should be set to true")
	})

	t.Run("IsPasswordlessLogin", func(t *testing.T) {
		// First set the flag to a known value
		err := repository.SetPasswordlessFlag(ctx, loginID, true)
		require.NoError(t, err)

		// Check if login is passwordless
		isPasswordless, err := repository.IsPasswordlessLogin(ctx, loginID)
		require.NoError(t, err)
		require.True(t, isPasswordless, "Login should be passwordless")

		// Change the flag
		err = repository.SetPasswordlessFlag(ctx, loginID, false)
		require.NoError(t, err)

		// Check again
		isPasswordless, err = repository.IsPasswordlessLogin(ctx, loginID)
		require.NoError(t, err)
		require.False(t, isPasswordless, "Login should not be passwordless")
	})
}
