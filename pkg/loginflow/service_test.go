package loginflow

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
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

// setupTestServices sets up all necessary services for testing
func setupTestServices(pool *pgxpool.Pool) *LoginFlowService {
	// Create necessary queries
	loginQueries := logindb.New(pool)
	mapperQueries := mapperdb.New(pool)

	// Create repository and services
	loginRepository := login.NewPostgresLoginRepository(loginQueries)
	mapperRepo := mapper.NewPostgresMapperRepository(mapperQueries)
	userMapper := mapper.NewDefaultUserMapper(mapperRepo)
	passwordManager := login.NewPasswordManager(loginQueries)

	// Create TwoFA queries and service
	twofaQueries := twofadb.New(pool)
	twofaRepo := twofa.NewPostgresTwoFARepository(twofaQueries)
	twoFaService := twofa.NewTwoFaService(twofaRepo)

	// Create device service with proper repository
	deviceRepository := device.NewPostgresDeviceRepository(pool)
	deviceService := device.NewDeviceService(deviceRepository)

	// Create token generators
	secret := "test-secret-key"
	issuer := "simple-idm-test"
	audience := "test-audience"

	accessTokenGen := tg.NewJwtTokenGenerator(secret, issuer, audience)
	refreshTokenGen := tg.NewJwtTokenGenerator(secret, issuer, audience)
	tempTokenGen := tg.NewTempTokenGenerator(secret, issuer, audience)
	logoutTokenGen := tg.NewJwtTokenGenerator(secret, issuer, audience)

	// Create token service
	tokenService := tg.NewDefaultTokenService(accessTokenGen, refreshTokenGen, tempTokenGen, logoutTokenGen, secret)

	// Create token cookie service
	tokenCookieService := tg.NewDefaultTokenCookieService("/", true, false, http.SameSiteStrictMode)

	// Create login service with all necessary components
	loginService := login.NewLoginServiceWithOptions(
		loginRepository,
		login.WithUserMapper(userMapper),
		login.WithPasswordManager(passwordManager),
	)

	return NewLoginFlowService(loginService, twoFaService, deviceService, tokenService, &tokenCookieService, userMapper)
}

// setupTestUser creates a single test user with a unique login
func setupTestUser(t *testing.T, pool *pgxpool.Pool, username, password string) mapper.User {
	ctx := context.Background()

	// Create necessary queries for logins service
	loginQueries := logindb.New(pool)
	loginsQueries := loginsdb.New(pool)
	iamQueries := iamdb.New(pool)

	// Create logins service
	loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)
	loginsService := logins.NewLoginsService(loginsRepo, loginQueries, nil)
	iamService := iam.NewIamServiceWithQueries(iamQueries)

	// Create login request
	request := logins.LoginCreateRequest{
		Username: username,
		Password: password,
	}

	// Create the login
	loginModel, err := loginsService.CreateLogin(ctx, request, "test-system")
	require.NoError(t, err)

	// Create a single user for this login
	email := fmt.Sprintf("%s@test.com", username)
	displayName := fmt.Sprintf("%s User", username)
	roleIds := []uuid.UUID{}

	userWithRoles, err := iamService.CreateUser(ctx, email, username, displayName, roleIds, loginModel.ID)
	require.NoError(t, err)

	// Convert IAM user to mapper user format
	loginIDStr := loginModel.ID
	if userWithRoles.LoginID != nil {
		loginIDStr = userWithRoles.LoginID.String()
	}

	mapperUser := mapper.User{
		UserId:      userWithRoles.ID.String(),
		LoginID:     loginIDStr,
		DisplayName: userWithRoles.Name,
		UserInfo: mapper.UserInfo{
			Email: userWithRoles.Email,
		},
		ExtraClaims: map[string]interface{}{
			"username": username,
			"roles":    []string{},
		},
		Roles: []string{},
	}

	return mapperUser
}

// createUserForExistingLogin creates an additional user for an existing login
func createUserForExistingLogin(t *testing.T, pool *pgxpool.Pool, loginID string, username, displayName string, userIndex int) mapper.User {
	ctx := context.Background()

	// Create necessary queries for IAM service
	iamQueries := iamdb.New(pool)
	iamService := iam.NewIamServiceWithQueries(iamQueries)

	// Create user for existing login
	email := fmt.Sprintf("%s+%d@test.com", username, userIndex)
	roleIds := []uuid.UUID{}

	userWithRoles, err := iamService.CreateUser(ctx, email, username, displayName, roleIds, loginID)
	require.NoError(t, err)

	// Convert IAM user to mapper user format
	loginIDStr := loginID
	if userWithRoles.LoginID != nil {
		loginIDStr = userWithRoles.LoginID.String()
	}

	mapperUser := mapper.User{
		UserId:      userWithRoles.ID.String(),
		LoginID:     loginIDStr,
		DisplayName: userWithRoles.Name,
		UserInfo: mapper.UserInfo{
			Email: userWithRoles.Email,
		},
		ExtraClaims: map[string]interface{}{
			"username": username,
			"roles":    []string{},
		},
		Roles: []string{},
	}

	return mapperUser
}

// setupTestUsers creates multiple test users with the same login by calling setupTestUser and creating additional users
func setupTestUsers(t *testing.T, pool *pgxpool.Pool, username, password string) []mapper.User {
	// Create the first user (which creates the login)
	firstUser := setupTestUser(t, pool, username, password)

	// Create additional users for the same login
	var users []mapper.User
	users = append(users, firstUser)

	// Create two more users with the same login ID for user switching tests
	userNames := []string{"Manager User", "Regular User"}
	for i, displayName := range userNames {
		additionalUser := createUserForExistingLogin(t, pool, firstUser.LoginID, username, displayName, i+2)
		users = append(users, additionalUser)
	}

	return users
}

// Test ProcessLogin method
func TestLoginFlowService_ProcessLogin(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	ctx := context.Background()

	t.Run("single user login", func(t *testing.T) {
		// Create single test user
		setupTestUser(t, pool, "singleuser", "Admin123.")

		// Setup services using the same database
		service := setupTestServices(pool)

		request := Request{
			Username:             "singleuser",
			Password:             "Admin123.",
			IPAddress:            "127.0.0.1",
			UserAgent:            "test-agent",
			DeviceFingerprintStr: "test-fingerprint",
		}

		result := service.ProcessLogin(ctx, request)

		require.True(t, result.Success)
		require.NotEmpty(t, result.Tokens)
		require.NotEmpty(t, result.Users)
		require.Len(t, result.Users, 1)
		require.False(t, result.RequiresUserSelection)
		require.Contains(t, result.Tokens, "access_token")
		require.Contains(t, result.Tokens, "refresh_token")
	})

	t.Run("multiple users login - requires user selection", func(t *testing.T) {
		// Create multiple test users with same loginID
		setupTestUsers(t, pool, "admin", "Admin123.")

		// Setup services using the same database
		service := setupTestServices(pool)

		request := Request{
			Username:             "admin",
			Password:             "Admin123.",
			IPAddress:            "127.0.0.1",
			UserAgent:            "test-agent",
			DeviceFingerprintStr: "test-fingerprint",
		}

		result := service.ProcessLogin(ctx, request)

		// For multi-user scenario, flow should not complete immediately
		require.False(t, result.Success)                 // Flow not complete yet
		require.True(t, result.RequiresUserSelection)    // User selection required
		require.Len(t, result.Users, 3)                  // All 3 users available for selection
		require.NotEmpty(t, result.Tokens)               // Temp token provided
		require.Contains(t, result.Tokens, "temp_token") // Specifically temp token
		require.False(t, result.RequiresTwoFA)           // 2FA not required in this test
	})

	t.Run("invalid credentials", func(t *testing.T) {
		// Setup services using the same database
		service := setupTestServices(pool)

		request := Request{
			Username:             "admin",
			Password:             "wrongpassword",
			IPAddress:            "127.0.0.1",
			UserAgent:            "test-agent",
			DeviceFingerprintStr: "test-fingerprint",
		}

		result := service.ProcessLogin(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})

	t.Run("nonexistent user", func(t *testing.T) {
		// Setup services using the same database
		service := setupTestServices(pool)

		request := Request{
			Username:             "nonexistent",
			Password:             "password",
			IPAddress:            "127.0.0.1",
			UserAgent:            "test-agent",
			DeviceFingerprintStr: "test-fingerprint",
		}

		result := service.ProcessLogin(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test ProcessMobileLogin method
func TestLoginFlowService_ProcessMobileLogin(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("successful mobile login", func(t *testing.T) {
		request := Request{
			Username:             "admin",
			Password:             "Admin123.",
			IPAddress:            "127.0.0.1",
			UserAgent:            "mobile-agent",
			DeviceFingerprintStr: "mobile-fingerprint",
		}

		result := service.ProcessMobileLogin(ctx, request)

		require.True(t, result.Success)
		require.NotEmpty(t, result.Tokens)
		require.NotEmpty(t, result.Users)
	})

	t.Run("invalid mobile credentials", func(t *testing.T) {
		request := Request{
			Username:             "admin",
			Password:             "wrongpassword",
			IPAddress:            "127.0.0.1",
			UserAgent:            "mobile-agent",
			DeviceFingerprintStr: "mobile-fingerprint",
		}

		result := service.ProcessMobileLogin(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test ProcessLoginByEmail method
func TestLoginFlowService_ProcessLoginByEmail(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()
	fingerprint := device.FingerprintData{
		UserAgent: "test-agent",
	}

	t.Run("successful email login", func(t *testing.T) {
		result := service.ProcessLoginByEmail(ctx, "admin@test.com", "Admin123.", "127.0.0.1", "test-agent", fingerprint)

		require.True(t, result.Success)
		require.NotEmpty(t, result.Tokens)
		require.NotEmpty(t, result.Users)
	})

	t.Run("invalid email credentials", func(t *testing.T) {
		result := service.ProcessLoginByEmail(ctx, "admin@test.com", "wrongpassword", "127.0.0.1", "test-agent", fingerprint)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test GenerateLoginTokens method
func TestLoginFlowService_GenerateLoginTokens(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("successful token generation", func(t *testing.T) {
		// First login to get a user
		request := Request{
			Username: "admin",
			Password: "Admin123.",
		}

		result := service.ProcessLogin(ctx, request)
		require.True(t, result.Success)
		require.NotEmpty(t, result.Users)

		user := result.Users[0]

		// Generate tokens
		tokens, err := service.GenerateLoginTokens(ctx, user)

		require.NoError(t, err)
		require.NotEmpty(t, tokens)
		require.Contains(t, tokens, "access_token")
		require.Contains(t, tokens, "refresh_token")
	})
}

// Test GenerateMobileLoginTokens method
func TestLoginFlowService_GenerateMobileLoginTokens(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)
	ctx := context.Background()

	t.Run("successful mobile token generation", func(t *testing.T) {
		// First login to get a user
		request := Request{
			Username: "admin",
			Password: "Admin123.",
		}

		result := service.ProcessLogin(ctx, request)
		require.True(t, result.Success)
		require.NotEmpty(t, result.Users)

		user := result.Users[0]

		// Generate mobile tokens
		tokens, err := service.GenerateMobileLoginTokens(ctx, user)

		require.NoError(t, err)
		require.NotEmpty(t, tokens)
		require.Contains(t, tokens, "access_token")
		require.Contains(t, tokens, "refresh_token")
	})
}

// Test ProcessTokenRefresh method
func TestLoginFlowService_ProcessTokenRefresh(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("successful token refresh", func(t *testing.T) {
		// First login to get tokens
		request := Request{
			Username: "admin",
			Password: "Admin123.",
		}

		result := service.ProcessLogin(ctx, request)
		require.True(t, result.Success)
		require.NotEmpty(t, result.Tokens)

		// Extract refresh token
		refreshToken, exists := result.Tokens["refresh_token"]
		require.True(t, exists)

		// Test token refresh
		refreshRequest := TokenRefreshRequest{
			RefreshToken: refreshToken.Token,
		}

		refreshResult := service.ProcessTokenRefresh(ctx, refreshRequest)

		require.True(t, refreshResult.Success)
		require.NotEmpty(t, refreshResult.Tokens)
		require.Contains(t, refreshResult.Tokens, "access_token")
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		request := TokenRefreshRequest{
			RefreshToken: "invalid-token",
		}

		result := service.ProcessTokenRefresh(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
		require.Equal(t, "invalid_token", result.ErrorResponse.Type)
	})
}

// Test ProcessMobileTokenRefresh method
func TestLoginFlowService_ProcessMobileTokenRefresh(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("successful mobile token refresh", func(t *testing.T) {
		// First mobile login to get tokens
		request := Request{
			Username: "admin",
			Password: "Admin123.",
		}

		result := service.ProcessMobileLogin(ctx, request)
		require.True(t, result.Success)
		require.NotEmpty(t, result.Tokens)

		// Extract refresh token
		refreshToken, exists := result.Tokens["refresh_token"]
		require.True(t, exists)

		// Test mobile token refresh
		refreshRequest := TokenRefreshRequest{
			RefreshToken: refreshToken.Token,
		}

		refreshResult := service.ProcessMobileTokenRefresh(ctx, refreshRequest)

		require.True(t, refreshResult.Success)
		require.NotEmpty(t, refreshResult.Tokens)
		require.Contains(t, refreshResult.Tokens, "access_token")
	})
}

// Test ProcessLogout method
func TestLoginFlowService_ProcessLogout(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("successful logout", func(t *testing.T) {
		result := service.ProcessLogout(ctx)

		require.True(t, result.Success)
		require.NotEmpty(t, result.Tokens)
		require.Contains(t, result.Tokens, "logout_token")
	})
}

// Test GetDeviceExpiration method
func TestLoginFlowService_GetDeviceExpiration(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	t.Run("get device expiration", func(t *testing.T) {
		expiration := service.GetDeviceExpiration()

		// Should return a valid duration (device service default)
		require.Greater(t, expiration, time.Duration(0))
	})
}

// Test GenerateUserAssociationToken method
func TestLoginFlowService_GenerateUserAssociationToken(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	t.Run("successful user association token generation", func(t *testing.T) {
		ctx := context.Background()

		// First login to get a user
		request := Request{
			Username: "admin",
			Password: "Admin123.",
		}

		result := service.ProcessLogin(ctx, request)
		require.True(t, result.Success)
		require.NotEmpty(t, result.Users)

		user := result.Users[0]
		userOptions := []mapper.User{user}

		// Generate user association token
		tokens, err := service.GenerateUserAssociationToken("test-login-id", user.UserId, userOptions)

		require.NoError(t, err)
		require.NotEmpty(t, tokens)
		require.Contains(t, tokens, "temp_token")
	})
}

// Test Process2FAValidation method
func TestLoginFlowService_Process2FAValidation(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("invalid temp token", func(t *testing.T) {
		request := TwoFAValidationRequest{
			TokenString:          "invalid-token",
			TwoFAType:            "totp",
			Passcode:             "123456",
			RememberDevice:       false,
			IPAddress:            "127.0.0.1",
			UserAgent:            "test-agent",
			DeviceFingerprintStr: "test-fingerprint",
		}

		result := service.Process2FAValidation(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test ProcessMobile2FAValidation method
func TestLoginFlowService_ProcessMobile2FAValidation(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("invalid temp token for mobile", func(t *testing.T) {
		request := TwoFAValidationRequest{
			TokenString:          "invalid-token",
			TwoFAType:            "totp",
			Passcode:             "123456",
			RememberDevice:       false,
			IPAddress:            "127.0.0.1",
			UserAgent:            "mobile-agent",
			DeviceFingerprintStr: "mobile-fingerprint",
		}

		result := service.ProcessMobile2FAValidation(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test ProcessUserSwitch method
func TestLoginFlowService_ProcessUserSwitch(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("invalid temp token for user switch", func(t *testing.T) {
		request := UserSwitchRequest{
			TokenString:          "invalid-token",
			TokenType:            "temp_token",
			TargetUserID:         "test-user-id",
			IPAddress:            "127.0.0.1",
			UserAgent:            "test-agent",
			DeviceFingerprintStr: "test-fingerprint",
		}

		result := service.ProcessUserSwitch(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test Process2FASend method
func TestLoginFlowService_Process2FASend(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("invalid temp token for 2FA send", func(t *testing.T) {
		request := TwoFASendRequest{
			TokenString:    "invalid-token",
			UserID:         "test-user-id",
			TwoFAType:      "sms",
			DeliveryOption: "phone",
		}

		result := service.Process2FASend(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test ProcessMobileUserLookup method
func TestLoginFlowService_ProcessMobileUserLookup(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	t.Run("invalid temp token for mobile user lookup", func(t *testing.T) {
		request := MobileUserLookupRequest{
			TokenString: "invalid-token",
			TokenType:   "temp_token",
		}

		result := service.ProcessMobileUserLookup(ctx, request)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}

// Test ProcessMagicLinkValidation method
func TestLoginFlowService_ProcessMagicLinkValidation(t *testing.T) {
	// Setup test database first
	pool, dbCleanup := setupTestDatabase(t)
	defer dbCleanup()

	// Create test user
	setupTestUser(t, pool, "admin", "Admin123.")

	// Setup services using the same database
	service := setupTestServices(pool)

	ctx := context.Background()

	fingerprint := device.FingerprintData{
		UserAgent: "test-agent",
	}

	t.Run("invalid magic link token", func(t *testing.T) {
		result := service.ProcessMagicLinkValidation(ctx, "invalid-magic-link-token", "127.0.0.1", "test-agent", fingerprint)

		require.False(t, result.Success)
		require.NotNil(t, result.ErrorResponse)
	})
}
