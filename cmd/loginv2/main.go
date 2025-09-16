package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"github.com/tendant/chi-demo/app"
	dbutils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/externalprovider"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	"github.com/tendant/simple-idm/pkg/iam"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/jwks"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	oauth2clientapi "github.com/tendant/simple-idm/pkg/oauth2client/api"
	"github.com/tendant/simple-idm/pkg/oidc"
	oidcapi "github.com/tendant/simple-idm/pkg/oidc/api"
	"github.com/tendant/simple-idm/pkg/signup"
	"github.com/tendant/simple-idm/pkg/user"
	"github.com/tendant/simple-idm/pkg/wellknown"

	// "github.com/tendant/simple-idm/pkg/impersonate/impersonatedb"

	"github.com/sosodev/duration"
	"github.com/tendant/simple-idm/pkg/device"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/loginflow"

	// loginapi "github.com/tendant/simple-idm/pkg/login/api"
	"github.com/tendant/simple-idm/pkg/login/loginapi"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/profile"
	profileapi "github.com/tendant/simple-idm/pkg/profile/api"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"github.com/tendant/simple-idm/pkg/role"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	"github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	twofaapi "github.com/tendant/simple-idm/pkg/twofa/api"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
)

type IdmDbConfig struct {
	Host     string `env:"IDM_PG_HOST" env-default:"localhost"`
	Port     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	Database string `env:"IDM_PG_DATABASE" env-default:"idm_db"`
	User     string `env:"IDM_PG_USER" env-default:"idm"`
	Password string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
}

func (d IdmDbConfig) toDbConfig() dbutils.DbConfig {
	return dbutils.DbConfig{
		Host:     d.Host,
		Port:     d.Port,
		Database: d.Database,
		User:     d.User,
		Password: d.Password,
	}
}

type JwtConfig struct {
	JwtSecret      string `env:"JWT_SECRET" env-default:"very-secure-jwt-secret"`
	CookieHttpOnly bool   `env:"COOKIE_HTTP_ONLY" env-default:"true"`
	CookieSecure   bool   `env:"COOKIE_SECURE" env-default:"true"`
	// Token expiry durations
	AccessTokenExpiry  string `env:"ACCESS_TOKEN_EXPIRY" env-default:"5m"`
	RefreshTokenExpiry string `env:"REFRESH_TOKEN_EXPIRY" env-default:"15m"`
	TempTokenExpiry    string `env:"TEMP_TOKEN_EXPIRY" env-default:"10m"`
	LogoutTokenExpiry  string `env:"LOGOUT_TOKEN_EXPIRY" env-default:"-1m"`
	Secret             string `env:"JWT_SECRET" env-default:"very-secure-jwt-secret"`
	Issuer             string `env:"JWT_ISSUER" env-default:"simple-idm"`
	Audience           string `env:"JWT_AUDIENCE" env-default:"simple-idm"`
}

type EmailConfig struct {
	Host     string `env:"EMAIL_HOST" env-default:"localhost"`
	Port     uint16 `env:"EMAIL_PORT" env-default:"1025"`
	Username string `env:"EMAIL_USERNAME" env-default:"noreply@example.com"`
	Password string `env:"EMAIL_PASSWORD" env-default:"pwd"`
	From     string `env:"EMAIL_FROM" env-default:"noreply@example.com"`
	TLS      bool   `env:"EMAIL_TLS" env-default:"false"`
}

type TwilioConfig struct {
	TwilioAccountSid string `env:"TWILIO_ACCOUNT_SID"`
	TwilioAuthToken  string `env:"TWILIO_AUTH_TOKEN"`
	TwilioFrom       string `env:"TWILIO_FROM"`
}

type PasswordComplexityConfig struct {
	RequiredDigit           bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_DIGIT" env-default:"true"`
	RequiredLowercase       bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_LOWERCASE" env-default:"true"`
	RequiredNonAlphanumeric bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_NON_ALPHANUMERIC" env-default:"true"`
	RequiredUppercase       bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_UPPERCASE" env-default:"true"`
	RequiredLength          int    `env:"PASSWORD_COMPLEXITY_REQUIRED_LENGTH" env-default:"8"`
	DisallowCommonPwds      bool   `env:"PASSWORD_COMPLEXITY_DISALLOW_COMMON_PWDS" env-default:"true"`
	MaxRepeatedChars        int    `env:"PASSWORD_COMPLEXITY_MAX_REPEATED_CHARS" env-default:"3"`
	HistoryCheckCount       int    `env:"PASSWORD_COMPLEXITY_HISTORY_CHECK_COUNT" env-default:"0"`
	ExpirationPeriod        string `env:"PASSWORD_COMPLEXITY_EXPIRATION_PERIOD" env-default:"P100Y"`      // 100 years
	MinPasswordAgePeriod    string `env:"PASSWORD_COMPLEXITY_MIN_PASSWORD_AGE_PERIOD" env-default:"PT0M"` // 0 minutes
}

type LoginConfig struct {
	MaxFailedAttempts        int    `env:"LOGIN_MAX_FAILED_ATTEMPTS" env-default:"10000"`
	LockoutDuration          string `env:"LOGIN_LOCKOUT_DURATION" env-default:"PT0M"`
	DeviceExpirationDays     string `env:"DEVICE_EXPIRATION_DAYS" env-default:"P90D"`
	RegistrationEnabled      bool   `env:"LOGIN_REGISTRATION_ENABLED" env-default:"false"`
	RegistrationDefaultRole  string `env:"LOGIN_REGISTRATION_DEFAULT_ROLE" env-default:"readonlyuser"`
	MagicLinkTokenExpiration string `env:"MAGIC_LINK_TOKEN_EXPIRATION" env-default:"PT6H"`
	PhoneVerificationSecret  string `env:"PHONE_VERIFICATION_SECRET" env-default:"secret"`
}

type OAuth2ClientConfig struct {
	// OAuth2 Client Secret Encryption Key (32 bytes base64 encoded)
	EncryptionKey string `env:"OAUTH2_CLIENT_ENCRYPTION_KEY"`
}

type ExternalProviderConfig struct {
	// Google OAuth2
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GoogleEnabled      bool   `env:"GOOGLE_ENABLED" env-default:"false"`

	// Microsoft OAuth2
	MicrosoftClientID     string `env:"MICROSOFT_CLIENT_ID"`
	MicrosoftClientSecret string `env:"MICROSOFT_CLIENT_SECRET"`
	MicrosoftEnabled      bool   `env:"MICROSOFT_ENABLED" env-default:"false"`

	// GitHub OAuth2
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
	GitHubEnabled      bool   `env:"GITHUB_ENABLED" env-default:"false"`

	// LinkedIn OAuth2
	LinkedInClientID     string `env:"LINKEDIN_CLIENT_ID"`
	LinkedInClientSecret string `env:"LINKEDIN_CLIENT_SECRET"`
	LinkedInEnabled      bool   `env:"LINKEDIN_ENABLED" env-default:"false"`

	// User Creation Settings
	DefaultRole string `env:"EXTERNAL_PROVIDER_DEFAULT_ROLE" env-default:"user"`
}

type Config struct {
	BaseUrl                  string `env:"BASE_URL" env-default:"http://localhost:4000"`
	FrontendUrl              string `env:"FRONTEND_URL" env-default:"http://localhost:3000"`
	IdmDbConfig              IdmDbConfig
	AppConfig                app.AppConfig
	JwtConfig                JwtConfig
	EmailConfig              EmailConfig
	PasswordComplexityConfig PasswordComplexityConfig
	LoginConfig              LoginConfig
	TwilioConfig             TwilioConfig
	OAuth2ClientConfig       OAuth2ClientConfig
	ExternalProviderConfig   ExternalProviderConfig
}

// loadEnvFile loads environment variables from .env file if it exists
// Only sets variables that are not already set in the environment
func loadEnvFile() {
	// Get the directory where the executable is located
	execPath, err := os.Executable()
	if err != nil {
		slog.Error("Failed to get executable path", "error", err)
		return
	}

	execDir := filepath.Dir(execPath)
	envFile := filepath.Join(execDir, ".env")

	// Also check current working directory
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		cwd, err := os.Getwd()
		if err != nil {
			slog.Error("Failed to get current working directory", "error", err)
			return
		}
		envFile = filepath.Join(cwd, ".env")
	}

	// Check if .env file exists
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		slog.Error("No .env file found", "path", envFile)
		return
	}

	slog.Info("Loading configuration from .env file", "path", envFile)

	// Load .env file using godotenv
	err = godotenv.Load(envFile)
	if err != nil {
		slog.Error("Failed to load .env file", "error", err, "path", envFile)
		return
	}

	slog.Info("Configuration loaded from .env file successfully")
}

func main() {

	// Create a logger with source enabled
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true, // Enables line number & file path
	}))

	// Set the logger as the default
	slog.SetDefault(logger)

	// Load .env file if it exists (before reading environment variables)
	loadEnvFile()

	config := Config{}
	cleanenv.ReadEnv(&config)

	server := app.DefaultApp()

	app.RoutesHealthz(server.R)
	app.RoutesHealthzReady(server.R)

	dbConfig := config.IdmDbConfig.toDbConfig()
	pool, err := dbutils.NewDbPool(context.Background(), dbConfig)
	if err != nil {
		slog.Error("Failed creating dbpool", "db", dbConfig.Database, "host", dbConfig.Host, "port", dbConfig.Port, "user", dbConfig.User)
		os.Exit(-1)
	}

	// Initialize database queries
	roleQueries := roledb.New(pool)
	iamQueries := iamdb.New(pool)
	loginQueries := logindb.New(pool)
	twofaQueries := twofadb.New(pool)
	mapperQueries := mapperdb.New(pool)

	// Initialize NotificationManager and register email notifier
	notificationManager, err := notice.NewNotificationManager(
		config.BaseUrl,
		notice.WithSMTP(notification.SMTPConfig{
			Host:     config.EmailConfig.Host,
			Port:     int(config.EmailConfig.Port),
			Username: config.EmailConfig.Username,
			Password: config.EmailConfig.Password,
			From:     config.EmailConfig.From,
			TLS:      config.EmailConfig.TLS,
		}),
		notice.WithTwilio(notification.TwilioConfig{
			TwilioAccountSid: config.TwilioConfig.TwilioAccountSid,
			TwilioAuthToken:  config.TwilioConfig.TwilioAuthToken,
			TwilioFrom:       config.TwilioConfig.TwilioFrom,
		}),
		notice.WithDefaultTemplates(),
	)
	if err != nil {
		slog.Error("Failed initialize notification manager", "err", err)
	}

	userMapper := mapper.NewDefaultUserMapper(mapperQueries)
	delegatedUserMapper := &mapper.DefaultDelegatedUserMapper{}

	// Create a password policy based on the environment
	passwordPolicy := createPasswordPolicy(&config.PasswordComplexityConfig)

	// Create a password manager with the policy checker
	passwordManager := login.NewPasswordManager(
		loginQueries,
	)

	// Create a policy checker
	policyChecker := login.NewDefaultPasswordPolicyChecker(passwordPolicy, nil)
	passwordManager.WithPolicyChecker(policyChecker)

	// Create login service with the custom password manager
	loginRepository := login.NewPostgresLoginRepository(loginQueries)
	// Use the same repository instance for both LoginRepository and UserRepository interfaces

	lockoutDuration, err := duration.Parse(config.LoginConfig.LockoutDuration)
	if err != nil {
		slog.Error("Failed to parse lockout duration", "err", err)
	}

	magicLinkExpiration, err := duration.Parse(config.LoginConfig.MagicLinkTokenExpiration)
	if err != nil {
		slog.Error("Failed to parse magic link token expiration", "err", err)
	}
	slog.Info("Magic link token expiration", "duration", magicLinkExpiration)
	loginService := login.NewLoginServiceWithOptions(
		loginRepository,
		login.WithNotificationManager(notificationManager),
		login.WithUserMapper(userMapper),
		login.WithDelegatedUserMapper(delegatedUserMapper),
		login.WithPasswordManager(passwordManager),
		login.WithMaxFailedAttempts(config.LoginConfig.MaxFailedAttempts),
		login.WithLockoutDuration(lockoutDuration.ToTimeDuration()),
		login.WithMagicLinkTokenExpiration(magicLinkExpiration.ToTimeDuration()), // 10 minutes for magic link token
	)
	slog.Info("Login service created", "maxFailedAttempts", config.LoginConfig.MaxFailedAttempts, "lockoutDuration", lockoutDuration.ToTimeDuration())

	// Create JWT token generator
	// tokenGenerator := tokengenerator.NewJwtTokenGenerator(
	// 	config.JwtConfig.JwtSecret,
	// 	"simple-idm", // Issuer
	// 	"simple-idm", // Audience
	// )

	// Initialize JWKS service for RSA key management with in-memory storage
	jwksService, err := jwks.NewJWKSServiceWithPostgresStorage(pool)
	if err != nil {
		slog.Error("Failed to initialize JWKS service", "error", err)
		os.Exit(-1)
	}

	// Get the active signing key for RSA token generation
	activeKey, err := jwksService.GetActiveSigningKey()
	if err != nil {
		slog.Error("Failed to get active signing key", "error", err)
		os.Exit(-1)
	}

	// Create RSA token generator using the active key
	rsaTokenGenerator := tokengenerator.NewRSATokenGenerator(
		activeKey.PrivateKey,
		activeKey.Kid,
		config.JwtConfig.Issuer,
		config.JwtConfig.Audience,
	)

	tempTokenGenerator := tokengenerator.NewTempRSATokenGenerator(
		activeKey.PrivateKey,
		activeKey.Kid,
		config.JwtConfig.Issuer,
		config.JwtConfig.Audience,
	)

	// Create token service with options
	tokenService := tokengenerator.NewTokenServiceWithOptions(
		rsaTokenGenerator,
		rsaTokenGenerator,
		tempTokenGenerator,
		rsaTokenGenerator,
		tokengenerator.WithAccessTokenExpiry(config.JwtConfig.AccessTokenExpiry),
		tokengenerator.WithRefreshTokenExpiry(config.JwtConfig.RefreshTokenExpiry),
		tokengenerator.WithTempTokenExpiry(config.JwtConfig.TempTokenExpiry),
		tokengenerator.WithLogoutTokenExpiry(config.JwtConfig.LogoutTokenExpiry),
		tokengenerator.WithPrivateKey(activeKey.PrivateKey),
	)
	tokenCookieService := tokengenerator.NewDefaultTokenCookieService(
		"/",
		config.JwtConfig.CookieHttpOnly,
		config.JwtConfig.CookieSecure,
		http.SameSiteLaxMode,
	)

	// Initialize device recognition service and routes
	// Configure device expiration using the value from config
	deviceExpirationDays := config.LoginConfig.DeviceExpirationDays
	// Declare the device expiry duration variable
	var deviceExpiryDuration time.Duration
	// Parse ISO 8601 duration using the duration package
	isoDuration, err := duration.Parse(deviceExpirationDays)
	if err != nil {
		slog.Error("Failed to parse device expiration duration", "error", err)
		// Default to 90 days if parsing fails
		deviceExpiryDuration = device.DefaultDeviceExpiryDuration
	} else {
		// Convert ISO duration to time.Duration
		deviceExpiryDuration = isoDuration.ToTimeDuration()
		slog.Info("Device expiration duration set", "duration", deviceExpiryDuration)
	}

	deviceRepositoryOptions := device.DeviceRepositoryOptions{
		ExpiryDuration: deviceExpiryDuration,
	}
	deviceRepository := device.NewPostgresDeviceRepositoryWithOptions(pool, deviceRepositoryOptions)
	deviceService := device.NewDeviceService(deviceRepository, loginRepository)

	twoFaService := twofa.NewTwoFaService(
		twofaQueries,
		twofa.WithNotificationManager(notificationManager),
		twofa.WithUserMapper(userMapper),
	)
	loginFlowService := loginflow.NewLoginFlowService(loginService, twoFaService, deviceService, tokenService, &tokenCookieService, userMapper)
	// Create a new handle with the domain login service directly
	loginHandle := loginapi.NewHandle(
		loginapi.WithLoginService(loginService),
		loginapi.WithLoginFlowService(loginFlowService),
		loginapi.WithTokenCookieService(tokenCookieService),
		loginapi.WithResponseHandler(loginapi.NewDefaultResponseHandler()),
	)

	// Initialize IAM repository and service
	iamService := iam.NewIamServiceWithQueriesAndGroups(iamQueries)
	userHandle := iamapi.NewHandle(iamService)

	// Initialize role repository and service
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	roleService := role.NewRoleService(roleRepo)
	roleHandle := roleapi.NewHandle(roleService)

	// Initialize logins management service and routes
	loginsQueries := loginsdb.New(pool)
	loginsServiceOptions := &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	}
	loginsService := logins.NewLoginsService(loginsQueries, loginQueries, loginsServiceOptions) // Pass nil for default options
	loginsHandle := logins.NewHandle(loginsService, *twoFaService)

	userService := user.NewUserService(iamService, loginsService, iamQueries)

	if exists, err := iamService.AnyUserExists(context.Background()); err != nil {
		slog.Error("Error checking user existence", "error", err)
	} else {
		if !exists {
			slog.Info("no user exists, creating first admin user")
			res, err := userService.CreateAdminUser(context.Background(), user.CreateAdminUserOptions{})
			if err != nil {
				slog.Error("Error creating admin user", "error", err)
			} else {
				slog.Info("Admin user created successfully", "user", res)
			}
		} else {
			slog.Info("User exists, skipping creation")
		}
	}

	signupHandle := signup.NewHandle(
		signup.WithIamService(*iamService),
		signup.WithRoleService(*roleService),
		signup.WithLoginsService(*loginsService),
		signup.WithRegistrationEnabled(config.LoginConfig.RegistrationEnabled),
		signup.WithDefaultRole(config.LoginConfig.RegistrationDefaultRole),
		signup.WithLoginService(*loginService),
	)

	// Initialize OAuth2 client service and OIDC handler
	var clientService *oauth2client.ClientService
	// Use PostgreSQL repository with encryption
	postgresRepo, err := oauth2client.NewPostgresOAuth2ClientRepository(pool, config.OAuth2ClientConfig.EncryptionKey)
	if err != nil {
		slog.Error("Failed to create PostgreSQL OAuth2 client repository", "error", err)
		os.Exit(-1)
	}
	clientService = oauth2client.NewClientService(postgresRepo)
	slog.Info("Using PostgreSQL OAuth2 client repository with encryption")

	// Setup default OAuth2 clients through the service layer
	// setupDefaultOAuth2Clients(clientService)

	// Create OIDC repository and service with RSA token generator
	oidcRepository := oidc.NewInMemoryOIDCRepository()
	oidcService := oidc.NewOIDCServiceWithOptions(
		oidcRepository,
		clientService,
		oidc.WithTokenGenerator(rsaTokenGenerator),
		oidc.WithBaseURL(config.BaseUrl),
		oidc.WithLoginURL(config.FrontendUrl+"/login"),
		oidc.WithUserMapper(userMapper),
		oidc.WithIssuer(config.JwtConfig.Issuer), // Use configured issuer
	)

	oidcHandle := oidcapi.NewOidcHandle(clientService, oidcService, oidcapi.WithJwksService(jwksService))

	// Initialize External Provider repository and service
	externalProviderRepository := externalprovider.NewInMemoryExternalProviderRepository()

	// Create external provider service
	slog.Info("Configuring external provider service",
		"user_creation_enabled", true,
		"auto_user_creation", true,
		"default_role", config.ExternalProviderConfig.DefaultRole)

	externalProviderService := externalprovider.NewExternalProviderService(
		externalProviderRepository,
		loginService,
		userMapper,
		externalprovider.WithBaseURL(config.BaseUrl),
		externalprovider.WithStateExpiration(10*time.Minute),
		externalprovider.WithHTTPClient(&http.Client{}),
		externalprovider.WithNotificationManager(notificationManager),
		externalprovider.WithUserCreationEnabled(true), // Security by default
		externalprovider.WithAutoUserCreation(true),    // Security by default
		externalprovider.WithLoginsService(loginsService),
		externalprovider.WithIamService(iamService),
		externalprovider.WithRoleService(roleService),
		externalprovider.WithDefaultRole(config.ExternalProviderConfig.DefaultRole), // Assign default role to new users
	)

	// Configure external providers based on environment variables
	setupExternalProviders(externalProviderService, &config.ExternalProviderConfig)

	// Create external provider API handler
	externalProviderHandle := externalProviderAPI.NewHandle(
		externalProviderService,
		loginService,
		tokenService,
		tokenCookieService,
	).WithFrontendURL(config.FrontendUrl)

	// Configure well-known endpoints for MCP compliance
	wellKnownConfig := wellknown.Config{
		ResourceURI:            config.BaseUrl,
		AuthorizationServerURI: config.BaseUrl,
		BaseURL:                config.BaseUrl,
		Scopes:                 []string{"openid", "profile", "email", "groups"},
		ResourceDocumentation:  config.BaseUrl + "/docs",
	}
	wellKnownHandler := wellknown.NewHandler(wellKnownConfig)

	// Register well-known endpoints for MCP compliance (public, no authentication required)
	server.R.Get("/.well-known/oauth-protected-resource", wellKnownHandler.ProtectedResourceMetadata)
	server.R.Get("/.well-known/oauth-authorization-server", wellKnownHandler.AuthorizationServerMetadata)
	server.R.Get("/.well-known/openid-configuration", wellKnownHandler.OpenIDConfiguration)

	slog.Info("Registration enabled", "enabled", config.LoginConfig.RegistrationEnabled)
	slog.Info("MCP Well-known endpoints configured", "base_url", config.BaseUrl)
	server.R.Mount("/api/idm/auth", loginapi.Handler(loginHandle))
	server.R.Mount("/api/idm/signup", signup.Handler(signupHandle))

	// Mount OIDC endpoints (public, no authentication required)
	server.R.Mount("/api/idm/oauth2", oidcapi.Handler(oidcHandle))

	// Mount external provider endpoints (public, no authentication required)
	server.R.Mount("/api/idm/external", externalProviderAPI.Handler(externalProviderHandle))

	tokenAuth := jwtauth.New("RS256", activeKey.PrivateKey, activeKey.PublicKey)

	server.R.Group(func(r chi.Router) {
		r.Use(client.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator(tokenAuth))
		r.Use(client.AuthUserMiddleware)
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
			if !ok {
				slog.Error("Failed getting AuthUser", "ok", ok)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			userInfo, err := loginService.GetMe(r.Context(), authUser.UserUuid)
			if err != nil {
				slog.Error("Failed getting me", "err", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			render.JSON(w, r, userInfo)
		})

		r.Get("/private", func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, http.StatusText(http.StatusOK))
		})

		profileQueries := profiledb.New(pool)
		profileRepo := profile.NewPostgresProfileRepository(profileQueries)
		profileService := profile.NewProfileServiceWithOptions(
			profileRepo,
			profile.WithPasswordManager(passwordManager),
			profile.WithUserMapper(userMapper),
			profile.WithNotificationManager(notificationManager),
		)
		responseHandler := profileapi.NewDefaultResponseHandler()
		profileHandle := profileapi.NewHandle(profileService, twoFaService, tokenService, tokenCookieService, loginService, deviceService, responseHandler, config.LoginConfig.PhoneVerificationSecret)
		r.Mount("/api/idm/profile", profileapi.Handler(profileHandle))

		// r.Mount("/auth", authpkg.Handler(authHandle))

		r.Mount("/idm/users", iamapi.SecureHandler(userHandle))

		// Create a secure handler for roles that uses the IAM admin middleware
		roleRouter := chi.NewRouter()
		roleRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", roleapi.Handler(roleHandle))
		})
		r.Mount("/idm/roles", roleRouter)

		// Initialize two factor authentication service and routes
		twoFaHandle := twofaapi.NewHandle(twoFaService, tokenService, tokenCookieService, userMapper)
		r.Mount("/idm/2fa", twofaapi.TwoFaHandler(twoFaHandle))

		deviceHandle := deviceapi.NewDeviceHandler(deviceService)
		r.Mount("/api/idm/device", deviceapi.Handler(deviceHandle))

		loginsRouter := chi.NewRouter()
		loginsRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", logins.Handler(loginsHandle))
		})
		r.Mount("/api/idm/logins", loginsRouter)

		// Initialize OAuth2 client management API (admin only)
		oauth2ClientHandle := oauth2clientapi.NewHandle(clientService)
		oauth2ClientRouter := chi.NewRouter()
		oauth2ClientRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", oauth2clientapi.Handler(oauth2ClientHandle))
		})
		r.Mount("/api/idm/oauth2-clients", oauth2ClientRouter)

		// Initialize impersonate service and routes
		// impersonateService := impersonate.NewService(userMapper, nil)
		// impersonateHandle := impersonateapi.NewHandler(impersonateService, tokenService, tokenCookieService)
		// r.Mount("/api/idm/impersonate", impersonateapi.Handler(impersonateHandle))

	})

	app.RoutesHealthzReady(server.R)
	server.Run()
}

func createPasswordPolicy(config *PasswordComplexityConfig) *login.PasswordPolicy {
	// If no config is provided, use the default policy
	if config == nil {
		return login.DefaultPasswordPolicy()
	}

	expirationPeriod, err := duration.Parse(config.ExpirationPeriod)
	if err != nil {
		slog.Error("Failed to parse expiration period", "err", err)
	}

	slog.Info("Expiration period", "expirationPeriod", expirationPeriod)

	minPasswordAgePeriod, err := duration.Parse(config.MinPasswordAgePeriod)
	if err != nil {
		slog.Error("Failed to parse min password age period", "err", err)
	}

	slog.Info("Min password age period", "minPasswordAgePeriod", minPasswordAgePeriod)

	// Create a policy based on the configuration
	// FIX-ME: hard code for bat now
	return &login.PasswordPolicy{
		MinLength:            config.RequiredLength,
		RequireUppercase:     config.RequiredUppercase,
		RequireLowercase:     config.RequiredLowercase,
		RequireDigit:         config.RequiredDigit,
		RequireSpecialChar:   config.RequiredNonAlphanumeric,
		DisallowCommonPwds:   config.DisallowCommonPwds,
		MaxRepeatedChars:     config.MaxRepeatedChars,
		HistoryCheckCount:    config.HistoryCheckCount,
		ExpirationPeriod:     expirationPeriod.ToTimeDuration(),
		CommonPasswordsPath:  "",
		MinPasswordAgePeriod: minPasswordAgePeriod.ToTimeDuration(),
	}
}

// setupExternalProviders configures external OAuth2 providers based on environment variables
func setupExternalProviders(service *externalprovider.ExternalProviderService, config *ExternalProviderConfig) {
	ctx := context.Background()

	// Configure Google OAuth2 provider
	if config.GoogleEnabled && config.GoogleClientID != "" && config.GoogleClientSecret != "" {
		googleProvider := &externalprovider.ExternalProvider{
			ID:           "google",
			Name:         "google",
			DisplayName:  "Google",
			ClientID:     config.GoogleClientID,
			ClientSecret: config.GoogleClientSecret,
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
			Scopes:       []string{"openid", "profile", "email"},
			Enabled:      true,
			IconURL:      "https://developers.google.com/identity/images/g-logo.png",
			Description:  "Sign in with your Google account",
		}

		slog.Info("Creating Google provider",
			"client_id", config.GoogleClientID,
			"client_secret_length", len(config.GoogleClientSecret),
			"enabled", config.GoogleEnabled)

		err := service.CreateProvider(ctx, googleProvider)
		if err != nil {
			slog.Error("Failed to create Google provider", "error", err)
		} else {
			slog.Info("Google OAuth2 provider configured successfully",
				"enabled", true,
				"provider_client_id", googleProvider.ClientID)
		}
	} else {
		slog.Warn("Google OAuth2 provider not configured",
			"enabled", config.GoogleEnabled,
			"client_id_empty", config.GoogleClientID == "",
			"client_secret_empty", config.GoogleClientSecret == "")
	}

	// Configure Microsoft OAuth2 provider
	if config.MicrosoftEnabled && config.MicrosoftClientID != "" && config.MicrosoftClientSecret != "" {
		microsoftProvider := &externalprovider.ExternalProvider{
			ID:           "microsoft",
			Name:         "microsoft",
			DisplayName:  "Microsoft",
			ClientID:     config.MicrosoftClientID,
			ClientSecret: config.MicrosoftClientSecret,
			AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
			Scopes:       []string{"openid", "profile", "email", "User.Read"},
			Enabled:      true,
			IconURL:      "https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png",
			Description:  "Sign in with your Microsoft account",
		}

		err := service.CreateProvider(ctx, microsoftProvider)
		if err != nil {
			slog.Error("Failed to create Microsoft provider", "error", err)
		} else {
			slog.Info("Microsoft OAuth2 provider configured", "enabled", true)
		}
	}

	// Configure GitHub OAuth2 provider
	if config.GitHubEnabled && config.GitHubClientID != "" && config.GitHubClientSecret != "" {
		githubProvider := &externalprovider.ExternalProvider{
			ID:           "github",
			Name:         "github",
			DisplayName:  "GitHub",
			ClientID:     config.GitHubClientID,
			ClientSecret: config.GitHubClientSecret,
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
			Scopes:       []string{"user:email"},
			Enabled:      true,
			IconURL:      "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
			Description:  "Sign in with your GitHub account",
		}

		err := service.CreateProvider(ctx, githubProvider)
		if err != nil {
			slog.Error("Failed to create GitHub provider", "error", err)
		} else {
			slog.Info("GitHub OAuth2 provider configured", "enabled", true)
		}
	}

	// Configure LinkedIn OAuth2 provider
	if config.LinkedInEnabled && config.LinkedInClientID != "" && config.LinkedInClientSecret != "" {
		linkedinProvider := &externalprovider.ExternalProvider{
			ID:           "linkedin",
			Name:         "linkedin",
			DisplayName:  "LinkedIn",
			ClientID:     config.LinkedInClientID,
			ClientSecret: config.LinkedInClientSecret,
			AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
			TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
			UserInfoURL:  "https://api.linkedin.com/v2/people/~",
			Scopes:       []string{"r_liteprofile", "r_emailaddress"},
			Enabled:      true,
			IconURL:      "https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Bug.svg.original.svg",
			Description:  "Sign in with your LinkedIn account",
		}

		err := service.CreateProvider(ctx, linkedinProvider)
		if err != nil {
			slog.Error("Failed to create LinkedIn provider", "error", err)
		} else {
			slog.Info("LinkedIn OAuth2 provider configured", "enabled", true)
		}
	}

	slog.Info("External provider setup completed",
		"google", config.GoogleEnabled,
		"microsoft", config.MicrosoftEnabled,
		"github", config.GitHubEnabled,
		"linkedin", config.LinkedInEnabled)
}
