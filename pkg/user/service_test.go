package user

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

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

// setupUserService sets up all necessary services for testing UserService
func setupUserService(pool *pgxpool.Pool) *UserService {
	// Create necessary queries
	loginQueries := logindb.New(pool)
	loginsQueries := loginsdb.New(pool)
	iamQueries := iamdb.New(pool)

	// Create services
	iamService := iam.NewIamServiceWithQueries(iamQueries)
	passwordManager := login.NewPasswordManager(loginQueries)
	loginsService := logins.NewLoginsService(loginsQueries, loginQueries, &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	})

	// Create user service
	return NewUserService(iamService, loginsService, iamQueries)
}

func TestUserService_CreateAdminUser(t *testing.T) {
	// Setup test database
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	ctx := context.Background()

	t.Run("create admin user with default values", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create admin user with default values
		result, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{})

		// Verify no error occurred
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify default values were used
		assert.Equal(t, "super", result.Username)
		assert.Equal(t, "super@example.com", result.Email)

		// Verify UUIDs are valid
		assert.NotEqual(t, uuid.Nil, result.UserID)
		assert.NotEqual(t, uuid.Nil, result.LoginID)
		assert.NotEqual(t, uuid.Nil, result.AdminRoleID)

		// Verify password was generated
		assert.NotEmpty(t, result.Password)
		assert.Len(t, result.Password, 16) // Should be 16 characters long

		// Verify password complexity (should contain different character types)
		password := result.Password
		hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
		hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		hasDigit := strings.ContainsAny(password, "0123456789")
		hasSymbol := strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?")

		assert.True(t, hasLower, "Password should contain lowercase letters")
		assert.True(t, hasUpper, "Password should contain uppercase letters")
		assert.True(t, hasDigit, "Password should contain digits")
		assert.True(t, hasSymbol, "Password should contain symbols")
	})

	t.Run("create admin user with custom values", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create admin user with custom values
		options := CreateAdminUserOptions{
			Username: "admin",
			Email:    "admin@mycompany.com",
		}

		result, err := userService.CreateAdminUser(ctx, options)

		// Verify no error occurred
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify custom values were used
		assert.Equal(t, "admin", result.Username)
		assert.Equal(t, "admin@mycompany.com", result.Email)

		// Verify UUIDs are valid
		assert.NotEqual(t, uuid.Nil, result.UserID)
		assert.NotEqual(t, uuid.Nil, result.LoginID)
		assert.NotEqual(t, uuid.Nil, result.AdminRoleID)

		// Verify password was generated
		assert.NotEmpty(t, result.Password)
		assert.Len(t, result.Password, 16)
	})

	t.Run("create admin user with custom username and default email pattern", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create admin user with custom username only
		options := CreateAdminUserOptions{
			Username: "sysadmin",
			// Email should default to "sysadmin@example.com"
		}

		result, err := userService.CreateAdminUser(ctx, options)

		// Verify no error occurred
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify values
		assert.Equal(t, "sysadmin", result.Username)
		assert.Equal(t, "sysadmin@example.com", result.Email)

		// Verify UUIDs are valid
		assert.NotEqual(t, uuid.Nil, result.UserID)
		assert.NotEqual(t, uuid.Nil, result.LoginID)
		assert.NotEqual(t, uuid.Nil, result.AdminRoleID)
	})

	t.Run("admin role is reused if it already exists", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create first admin user
		result1, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "admin1",
		})
		require.NoError(t, err)

		// Create second admin user
		result2, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "admin2",
		})
		require.NoError(t, err)

		// Both should use the same admin role
		assert.Equal(t, result1.AdminRoleID, result2.AdminRoleID)

		// But should have different user and login IDs
		assert.NotEqual(t, result1.UserID, result2.UserID)
		assert.NotEqual(t, result1.LoginID, result2.LoginID)
	})

	t.Run("duplicate username should fail", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create first admin user
		_, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "duplicate",
		})
		require.NoError(t, err)

		// Try to create second admin user with same username
		_, err = userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "duplicate",
		})

		// Should fail due to duplicate username
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create login")
	})

	t.Run("verify admin role is created correctly", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create admin user with unique username
		result, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "roletest",
		})
		require.NoError(t, err)

		// Verify the admin role exists and has correct name
		iamQueries := iamdb.New(pool)
		role, err := iamQueries.GetRoleById(ctx, result.AdminRoleID)
		require.NoError(t, err)
		assert.Equal(t, "admin", role.Name)
	})

	t.Run("verify user is associated with admin role", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create admin user with unique username
		result, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "roleassoc",
		})
		require.NoError(t, err)

		// Verify user has admin role
		iamService := iam.NewIamServiceWithQueries(iamdb.New(pool))
		userWithRoles, err := iamService.GetUser(ctx, result.UserID)
		require.NoError(t, err)

		// Should have exactly one role (admin)
		require.Len(t, userWithRoles.Roles, 1)
		assert.Equal(t, result.AdminRoleID, userWithRoles.Roles[0].ID)
		assert.Equal(t, "admin", userWithRoles.Roles[0].Name)
	})

	t.Run("verify login can be used for authentication", func(t *testing.T) {
		userService := setupUserService(pool)

		// Create admin user with unique username
		result, err := userService.CreateAdminUser(ctx, CreateAdminUserOptions{
			Username: "authtest",
		})
		require.NoError(t, err)

		// Try to authenticate with the created login
		loginService := login.NewLoginServiceWithOptions(
			login.NewPostgresLoginRepository(logindb.New(pool)),
		)

		// Find the login by username
		loginEntity, err := loginService.FindLoginByUsername(ctx, result.Username)
		require.NoError(t, err)

		// Verify password
		valid, err := loginService.CheckPasswordByLoginId(ctx, loginEntity.ID, result.Password, string(loginEntity.Password))
		require.NoError(t, err)
		assert.True(t, valid, "Generated password should be valid for authentication")
	})
}

func TestUserService_generateSecurePassword(t *testing.T) {
	userService := &UserService{}

	t.Run("password generation produces valid passwords", func(t *testing.T) {
		// Generate multiple passwords to test consistency
		passwords := make([]string, 10)
		for i := 0; i < 10; i++ {
			password, err := userService.generateSecurePassword()
			require.NoError(t, err)
			passwords[i] = password
		}

		// Verify all passwords meet requirements
		for i, password := range passwords {
			t.Run(fmt.Sprintf("password_%d", i), func(t *testing.T) {
				// Check length
				assert.Len(t, password, 16)

				// Check character variety
				hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
				hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
				hasDigit := strings.ContainsAny(password, "0123456789")
				hasSymbol := strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?")

				assert.True(t, hasLower, "Password should contain lowercase letters")
				assert.True(t, hasUpper, "Password should contain uppercase letters")
				assert.True(t, hasDigit, "Password should contain digits")
				assert.True(t, hasSymbol, "Password should contain symbols")
			})
		}

		// Verify passwords are unique (very high probability)
		uniquePasswords := make(map[string]bool)
		for _, password := range passwords {
			uniquePasswords[password] = true
		}
		assert.Len(t, uniquePasswords, len(passwords), "All generated passwords should be unique")
	})
}

func TestUserService_ensureAdminRole(t *testing.T) {
	// Setup test database
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	ctx := context.Background()
	userService := setupUserService(pool)

	t.Run("creates admin role when it doesn't exist", func(t *testing.T) {
		// Ensure no admin role exists initially
		iamQueries := iamdb.New(pool)
		roles, err := iamQueries.FindRoles(ctx)
		require.NoError(t, err)

		// Verify no admin role exists
		for _, role := range roles {
			assert.NotEqual(t, "admin", strings.ToLower(role.Name))
		}

		// Create admin role
		adminRoleID, err := userService.ensureAdminRole(ctx)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, adminRoleID)

		// Verify admin role was created
		role, err := iamQueries.GetRoleById(ctx, adminRoleID)
		require.NoError(t, err)
		assert.Equal(t, "admin", role.Name)
	})

	t.Run("returns existing admin role ID when it already exists", func(t *testing.T) {
		// Create admin role first time
		adminRoleID1, err := userService.ensureAdminRole(ctx)
		require.NoError(t, err)

		// Call again - should return same ID
		adminRoleID2, err := userService.ensureAdminRole(ctx)
		require.NoError(t, err)

		assert.Equal(t, adminRoleID1, adminRoleID2)
	})

	t.Run("handles case-insensitive admin role matching", func(t *testing.T) {
		// Create a role with different case
		iamQueries := iamdb.New(pool)
		upperAdminRoleID, err := iamQueries.CreateRole(ctx, "ADMIN")
		require.NoError(t, err)

		// ensureAdminRole should find the existing role regardless of case
		foundRoleID, err := userService.ensureAdminRole(ctx)
		require.NoError(t, err)

		assert.Equal(t, upperAdminRoleID, foundRoleID)
	})
}

func TestUserService_randomCharFromString(t *testing.T) {
	userService := &UserService{}

	t.Run("returns character from string", func(t *testing.T) {
		testString := "abc123"
		char, err := userService.randomCharFromString(testString)
		require.NoError(t, err)
		assert.Contains(t, testString, string(char))
	})

	t.Run("handles empty string", func(t *testing.T) {
		_, err := userService.randomCharFromString("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty string provided")
	})

	t.Run("produces varied results", func(t *testing.T) {
		testString := "abcdefghijklmnopqrstuvwxyz"
		results := make(map[byte]bool)

		// Generate many characters to test randomness
		for i := 0; i < 100; i++ {
			char, err := userService.randomCharFromString(testString)
			require.NoError(t, err)
			results[char] = true
		}

		// Should have generated multiple different characters
		assert.Greater(t, len(results), 1, "Should generate varied characters")
	})
}

func TestUserService_shuffleBytes(t *testing.T) {
	userService := &UserService{}

	t.Run("shuffles byte array", func(t *testing.T) {
		original := []byte("abcdefghijklmnop")
		toShuffle := make([]byte, len(original))
		copy(toShuffle, original)

		userService.shuffleBytes(toShuffle)

		// Should contain same characters
		assert.Len(t, toShuffle, len(original))
		for _, b := range original {
			assert.Contains(t, toShuffle, b)
		}

		// Should be different order (very high probability)
		// Note: There's a tiny chance they could be the same, but extremely unlikely
		different := false
		for i, b := range toShuffle {
			if b != original[i] {
				different = true
				break
			}
		}
		assert.True(t, different, "Shuffled array should be in different order")
	})

	t.Run("handles single element", func(t *testing.T) {
		single := []byte("a")
		userService.shuffleBytes(single)
		assert.Equal(t, []byte("a"), single)
	})

	t.Run("handles empty array", func(t *testing.T) {
		empty := []byte{}
		userService.shuffleBytes(empty)
		assert.Equal(t, []byte{}, empty)
	})
}
