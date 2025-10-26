package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/tendant/chi-demo/app"
	"github.com/tendant/simple-idm/pkg/bootstrap"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/config"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/iam"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/jwks"
	"github.com/tendant/simple-idm/pkg/login"
	loginapi "github.com/tendant/simple-idm/pkg/login/loginapi"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/loginflow"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	oauth2clientapi "github.com/tendant/simple-idm/pkg/oauth2client/api"
	"github.com/tendant/simple-idm/pkg/oidc"
	oidcapi "github.com/tendant/simple-idm/pkg/oidc/api"
	"github.com/tendant/simple-idm/pkg/role"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	"github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/tendant/simple-idm/pkg/signup"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/user"
	"github.com/tendant/simple-idm/pkg/wellknown"
)

type Config struct {
	// Application
	BaseURL     string `env:"BASE_URL" env-default:"http://localhost:4000"`
	FrontendURL string `env:"FRONTEND_URL" env-default:"http://localhost:3000"`

	// Database
	DBHost     string `env:"IDM_PG_HOST" env-default:"localhost"`
	DBPort     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	DBDatabase string `env:"IDM_PG_DATABASE" env-default:"idm_db"`
	DBUser     string `env:"IDM_PG_USER" env-default:"idm"`
	DBPassword string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
	DBSchema   string `env:"IDM_PG_SCHEMA" env-default:"public"`

	// Email
	EmailHost     string `env:"EMAIL_HOST" env-default:"localhost"`
	EmailPort     uint16 `env:"EMAIL_PORT" env-default:"1025"`
	EmailUsername string `env:"EMAIL_USERNAME" env-default:""`
	EmailPassword string `env:"EMAIL_PASSWORD" env-default:""`
	EmailFrom     string `env:"EMAIL_FROM" env-default:"noreply@example.com"`
	EmailTLS      bool   `env:"EMAIL_TLS" env-default:"false"`

	// JWT (RSA-based signing with RS256)
	JWTIssuer  string `env:"JWT_ISSUER" env-default:"quick-idm"`
	JWTKeyFile string `env:"JWT_KEY_FILE" env-default:"jwt-private.pem"`

	// Token Expiry
	AccessTokenExpiry  string `env:"ACCESS_TOKEN_EXPIRY" env-default:"15m"`
	RefreshTokenExpiry string `env:"REFRESH_TOKEN_EXPIRY" env-default:"24h"`
	TempTokenExpiry    string `env:"TEMP_TOKEN_EXPIRY" env-default:"10m"`

	// Registration
	RegistrationEnabled     bool   `env:"REGISTRATION_ENABLED" env-default:"true"`
	RegistrationDefaultRole string `env:"REGISTRATION_DEFAULT_ROLE" env-default:"user"`

	// Magic Link
	MagicLinkExpiration string `env:"MAGIC_LINK_EXPIRATION" env-default:"1h"`

	// Cookies
	CookieSecure   bool `env:"COOKIE_SECURE" env-default:"false"`
	CookieHttpOnly bool `env:"COOKIE_HTTP_ONLY" env-default:"true"`

	// Initial Admin User
	AdminUsername string `env:"ADMIN_USERNAME" env-default:""`
	AdminPassword string `env:"ADMIN_PASSWORD" env-default:""`
	AdminEmail    string `env:"ADMIN_EMAIL" env-default:""`

	// Admin Roles
	AdminRoleNames string `env:"ADMIN_ROLE_NAMES" env-default:"admin,superadmin"`

	// Server
	AppConfig app.AppConfig
}

func (c *Config) toDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&search_path=%s,public",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBDatabase, c.DBSchema)
}

func main() {
	// Setup logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))
	slog.SetDefault(logger)

	slog.Info("Starting Quick IDM Service")
	slog.Info("=" + string(make([]byte, 60)) + "=")

	// Load .env file
	loadEnvFile()

	// Load configuration
	config := Config{}
	if err := cleanenv.ReadEnv(&config); err != nil {
		slog.Error("Failed to read configuration", "error", err)
		os.Exit(1)
	}

	// Bootstrap RSA key (auto-generate if missing)
	rsaResult, err := bootstrap.BootstrapRSAKey(bootstrap.RSAKeyConfig{
		KeyFile:     config.JWTKeyFile,
		KeySize:     2048,
		KeyIDPrefix: "quick-idm",
	})
	if err != nil {
		slog.Error("Failed to bootstrap RSA key", "error", err)
		os.Exit(1)
	}

	// Display RSA key info (quiet mode - just one line)
	bootstrap.PrintRSAKeyQuietInfo(rsaResult)

	// Extract key and keyID for later use
	privateKey := rsaResult.PrivateKey
	keyID := rsaResult.KeyID

	// Initialize database connection
	dbURL := config.toDatabaseURL()
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		slog.Error("Failed to connect to database",
			"host", config.DBHost,
			"port", config.DBPort,
			"database", config.DBDatabase,
			"schema", config.DBSchema,
			"error", err)
		os.Exit(1)
	}
	defer pool.Close()

	slog.Info("Database connected", "database", config.DBDatabase, "schema", config.DBSchema)

	// Initialize core services
	services := initializeServices(pool, &config, privateKey, keyID)

	// Bootstrap admin roles and user if needed
	bootstrapAdminRolesAndUser(services.iamService, services.userService, &config)

	// Setup HTTP server
	server := app.DefaultApp()
	setupRoutes(server.R, services, &config)

	slog.Info("=" + string(make([]byte, 60)) + "=")
	slog.Info("Quick IDM Service Ready")
	slog.Info("Base URL: " + config.BaseURL)
	slog.Info("OIDC Discovery: " + config.BaseURL + "/.well-known/openid-configuration")
	slog.Info("=" + string(make([]byte, 60)) + "=")

	// Start server
	server.Run()
}

// Services contains all initialized services for the application
// Some services are stored for future extensibility even if not currently used
type Services struct {
	// Core services (actively used)
	iamService          *iam.IamService
	loginService        *login.LoginService
	loginFlowService    *loginflow.LoginFlowService
	loginsService       *logins.LoginsService
	roleService         *role.RoleService
	tokenCookieService  tokengenerator.TokenCookieService
	oauth2ClientService *oauth2client.ClientService
	oidcService         *oidc.OIDCService
	jwksService         *jwks.JWKSService
	userService         *user.UserService

	// Optional services (available but not directly accessed - passed to sub-services)
	// These can be nil in minimal configurations
	tokenService tokengenerator.TokenService // Used by sub-services (loginFlowService, oidcService)
	userMapper   mapper.UserMapper           // Used by sub-services (loginService, oidcService)
}

func initializeServices(pool *pgxpool.Pool, config *Config, privateKey *rsa.PrivateKey, keyID string) *Services {
	// Initialize database queries (sqlc generated)
	iamQueries := iamdb.New(pool)
	loginQueries := logindb.New(pool)
	loginsQueries := loginsdb.New(pool)
	roleQueries := roledb.New(pool)
	mapperQueries := mapperdb.New(pool)

	// Create repositories (following repository pattern)
	iamRepo := iam.NewPostgresIamRepository(iamQueries)
	iamGroupRepo := iam.NewPostgresIamGroupRepository(iamQueries)
	loginRepository := login.NewPostgresLoginRepository(loginQueries)
	loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	mapperRepo := mapper.NewPostgresMapperRepository(mapperQueries)

	// Notification manager
	notificationManager, err := notice.NewNotificationManager(
		config.FrontendURL,
		notice.WithSMTP(notification.SMTPConfig{
			Host:     config.EmailHost,
			Port:     int(config.EmailPort),
			Username: config.EmailUsername,
			Password: config.EmailPassword,
			From:     config.EmailFrom,
			TLS:      config.EmailTLS,
		}),
		notice.WithDefaultTemplates(),
	)
	if err != nil {
		slog.Error("Failed to initialize notification manager", "error", err)
	}

	// User mapper
	userMapper := mapper.NewDefaultUserMapper(mapperRepo)
	delegatedUserMapper := &mapper.DefaultDelegatedUserMapper{}

	// Password management - use no-op policy for quick start
	// This accepts any non-empty password (even "a" or "123")
	// Perfect for development/testing - NOT recommended for production
	// To enable password validation, set PASSWORD_POLICY_ENABLED=true in environment
	passwordPolicy := login.NoOpPasswordPolicy()

	passwordManager := login.NewPasswordManagerWithRepository(loginRepository)
	policyChecker := login.NewDefaultPasswordPolicyChecker(passwordPolicy, nil)
	passwordManager.WithPolicyChecker(policyChecker)

	// Login service
	magicLinkExpiration := 1 * time.Hour
	loginService := login.NewLoginServiceWithOptions(
		loginRepository,
		login.WithNotificationManager(notificationManager),
		login.WithUserMapper(userMapper),
		login.WithDelegatedUserMapper(delegatedUserMapper),
		login.WithPasswordManager(passwordManager),
		login.WithMaxFailedAttempts(10),
		login.WithLockoutDuration(5*time.Minute),
		login.WithMagicLinkTokenExpiration(magicLinkExpiration),
	)

	// JWKS service
	jwksService, err := jwks.NewJWKSServiceWithKey(&jwks.KeyPair{
		Kid:        keyID,
		Alg:        "RS256",
		PrivateKey: privateKey,
	})
	if err != nil {
		slog.Error("Failed to initialize JWKS service", "error", err)
		os.Exit(1)
	}

	activeKey, _ := jwksService.GetActiveSigningKey()

	// Token generators
	rsaTokenGenerator := tokengenerator.NewRSATokenGenerator(
		activeKey.PrivateKey,
		activeKey.Kid,
		config.JWTIssuer,
		config.JWTIssuer,
	)

	tempTokenGenerator := tokengenerator.NewTempRSATokenGenerator(
		activeKey.PrivateKey,
		activeKey.Kid,
		config.JWTIssuer,
		config.JWTIssuer,
	)

	tokenService := tokengenerator.NewTokenServiceWithOptions(
		rsaTokenGenerator,
		rsaTokenGenerator,
		tempTokenGenerator,
		rsaTokenGenerator,
		tokengenerator.WithAccessTokenExpiry(config.AccessTokenExpiry),
		tokengenerator.WithRefreshTokenExpiry(config.RefreshTokenExpiry),
		tokengenerator.WithTempTokenExpiry(config.TempTokenExpiry),
		tokengenerator.WithLogoutTokenExpiry("-1m"),
		tokengenerator.WithPrivateKey(activeKey.PrivateKey),
	)

	tokenCookieService := tokengenerator.NewDefaultTokenCookieService(
		"/",
		config.CookieHttpOnly,
		config.CookieSecure,
		http.SameSiteLaxMode,
	)

	// Use no-op services for features not needed in quick mode
	// This eliminates the need for twofa/device database tables and initialization
	twoFaService := twofa.NewNoOpTwoFactorService()

	// For DeviceService, we'll create a minimal instance with no-op repository
	// This is simpler than modifying loginflow to accept nil
	deviceRepository := device.NewNoOpDeviceRepository()
	deviceService := device.NewDeviceService(deviceRepository, loginRepository)

	// LoginFlow service (with no-op 2FA and minimal device service)
	loginFlowService := loginflow.NewLoginFlowService(
		loginService,
		twoFaService,
		deviceService,
		tokenService,
		&tokenCookieService,
		userMapper,
	)

	// IAM service (with repository pattern)
	iamService := iam.NewIamServiceWithOptions(
		iamRepo,
		iam.WithGroupRepository(iamGroupRepo),
	)

	// Role service
	roleService := role.NewRoleService(roleRepo)

	// Logins service
	loginsServiceOptions := &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	}
	loginsService := logins.NewLoginsService(loginsRepo, nil, loginsServiceOptions)

	// User service
	userService := user.NewUserService(iamService, loginsService)

	// OAuth2 client service - using environment-based configuration
	// No database or encryption needed - clients configured via env vars
	oauth2Repo, err := oauth2client.NewEnvOAuth2ClientRepository()
	if err != nil {
		slog.Error("Failed to create OAuth2 client repository", "error", err)
		os.Exit(1)
	}
	oauth2ClientService := oauth2client.NewClientService(oauth2Repo)
	slog.Info("OAuth2 clients loaded from environment variables")

	// OIDC service
	oidcRepository := oidc.NewInMemoryOIDCRepository()
	oidcService := oidc.NewOIDCServiceWithOptions(
		oidcRepository,
		oauth2ClientService,
		oidc.WithTokenGenerator(rsaTokenGenerator),
		oidc.WithBaseURL(config.BaseURL),
		oidc.WithLoginURL(config.FrontendURL+"/login"),
		oidc.WithUserMapper(userMapper),
		oidc.WithIssuer(config.JWTIssuer),
	)

	return &Services{
		iamService:          iamService,
		loginService:        loginService,
		loginFlowService:    loginFlowService,
		loginsService:       loginsService,
		roleService:         roleService,
		tokenService:        tokenService,
		tokenCookieService:  tokenCookieService,
		oauth2ClientService: oauth2ClientService,
		oidcService:         oidcService,
		jwksService:         jwksService,
		userService:         userService,
		userMapper:          userMapper,
	}
}

func setupRoutes(r *chi.Mux, services *Services, appConfig *Config) {
	// Parse admin role names from config
	adminRoles := config.ParseAdminRoleNames(appConfig.AdminRoleNames)
	slog.Info("Configuring admin role middleware", "admin_roles", adminRoles)

	// Health check endpoints
	app.RoutesHealthz(r)
	app.RoutesHealthzReady(r)

	// Well-known endpoints (OIDC/OAuth2 discovery)
	wellKnownConfig := wellknown.Config{
		ResourceURI:            appConfig.BaseURL,
		AuthorizationServerURI: appConfig.BaseURL,
		BaseURL:                appConfig.BaseURL,
		Scopes:                 []string{"openid", "profile", "email"},
		ResourceDocumentation:  appConfig.BaseURL + "/docs",
	}
	wellKnownHandler := wellknown.NewHandler(wellKnownConfig)
	r.Get("/.well-known/oauth-protected-resource", wellKnownHandler.ProtectedResourceMetadata)
	r.Get("/.well-known/oauth-authorization-server", wellKnownHandler.AuthorizationServerMetadata)
	r.Get("/.well-known/openid-configuration", wellKnownHandler.OpenIDConfiguration)

	// Login API handler (uses loginflow service for magic link validation)
	loginHandle := loginapi.NewHandle(
		loginapi.WithLoginService(services.loginService),
		loginapi.WithLoginFlowService(services.loginFlowService),
		loginapi.WithTokenCookieService(services.tokenCookieService),
		loginapi.WithResponseHandler(loginapi.NewDefaultResponseHandler()),
	)

	// Signup handler
	signupHandle := signup.NewHandle(
		signup.WithIamService(*services.iamService),
		signup.WithRoleService(*services.roleService),
		signup.WithLoginsService(*services.loginsService),
		signup.WithRegistrationEnabled(appConfig.RegistrationEnabled),
		signup.WithDefaultRole(appConfig.RegistrationDefaultRole),
		signup.WithLoginService(*services.loginService),
	)

	// OIDC handler
	oidcHandle := oidcapi.NewOidcHandle(
		services.oauth2ClientService,
		services.oidcService,
		oidcapi.WithJwksService(services.jwksService),
	)

	// Public routes (no authentication)
	r.Route("/api/auth", func(r chi.Router) {
		// Password login
		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.PostLogin(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})

		// Magic link endpoints
		r.Post("/magic-link/email", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.InitiateMagicLinkLoginByEmail(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
		r.Get("/magic-link/validate", func(w http.ResponseWriter, r *http.Request) {
			params := loginapi.ValidateMagicLinkTokenParams{
				Token: r.URL.Query().Get("token"),
			}
			resp := loginHandle.ValidateMagicLinkToken(w, r, params)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})

		// Token refresh
		r.Post("/token/refresh", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.PostTokenRefresh(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})

		// Logout
		r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.PostLogout(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
	})

	// Signup routes (public)
	r.Route("/api/signup", func(r chi.Router) {
		r.Post("/passwordless", func(w http.ResponseWriter, r *http.Request) {
			resp := signupHandle.RegisterUserPasswordless(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
		r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
			resp := signupHandle.RegisterUser(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
	})

	// OAuth2/OIDC endpoints (public)
	r.Mount("/api/oauth2", oidcapi.Handler(oidcHandle))

	// JWT authentication setup
	activeKey, _ := services.jwksService.GetActiveSigningKey()
	rsaAuth := jwtauth.New("RS256", activeKey.PrivateKey, activeKey.PublicKey)

	// Protected routes (require authentication)
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(rsaAuth))
		r.Use(jwtauth.Authenticator(rsaAuth))
		r.Use(client.AuthUserMiddleware)

		// Current user info
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			userInfo, err := services.loginService.GetMe(r.Context(), authUser.UserUuid)
			if err != nil {
				slog.Error("Failed to get user info", "error", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			render.JSON(w, r, userInfo)
		})

		// IAM routes (user management)
		userHandle := iamapi.NewHandle(services.iamService)
		r.Mount("/api/users", iamapi.SecureHandler(userHandle))

		// Role routes (admin only)
		roleHandle := roleapi.NewHandle(services.roleService)
		roleRouter := chi.NewRouter()
		roleRouter.Group(func(r chi.Router) {
			r.Use(client.NewAdminRoleMiddleware(adminRoles))
			r.Mount("/", roleapi.Handler(roleHandle))
		})
		r.Mount("/api/roles", roleRouter)

		// OAuth2 client management (admin only)
		oauth2ClientHandle := oauth2clientapi.NewHandle(services.oauth2ClientService)
		oauth2ClientRouter := chi.NewRouter()
		oauth2ClientRouter.Group(func(r chi.Router) {
			r.Use(client.NewAdminRoleMiddleware(adminRoles))
			r.Mount("/", oauth2clientapi.Handler(oauth2ClientHandle))
		})
		r.Mount("/api/oauth2-clients", oauth2ClientRouter)
	})
}

// bootstrapAdminRolesAndUser ensures admin roles exist and creates the first admin user if needed
func bootstrapAdminRolesAndUser(iamService *iam.IamService, userService *user.UserService, appConfig *Config) {
	ctx := context.Background()

	// Parse admin role names from configuration
	adminRoles := config.ParseAdminRoleNames(appConfig.AdminRoleNames)

	// Build bootstrap configuration
	bootstrapConfig := bootstrap.AdminBootstrapConfig{
		AdminRoleNames: adminRoles,
		AdminUsername:  appConfig.AdminUsername,
		AdminEmail:     appConfig.AdminEmail,
		AdminPassword:  appConfig.AdminPassword,
		IamService:     iamService,
		UserService:    userService,
	}

	// Execute bootstrap
	result, err := bootstrap.BootstrapAdminRolesAndUser(ctx, bootstrapConfig)
	if err != nil {
		slog.Error("Failed to bootstrap admin roles and user", "error", err)
		// Don't exit - allow service to continue (admin can be created via API)
		return
	}

	// Display results if admin was created
	if result.UserCreated {
		bootstrap.PrintBootstrapResult(result)
		bootstrap.LogBootstrapSummary(result)
	}
}

// Note: ensureRSAKey has been replaced with bootstrap.BootstrapRSAKey
// See pkg/bootstrap/rsa.go for the new implementation

// loadEnvFile loads environment variables from .env file if it exists
func loadEnvFile() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}

	execDir := filepath.Dir(execPath)
	envFile := filepath.Join(execDir, ".env")

	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		cwd, _ := os.Getwd()
		envFile = filepath.Join(cwd, ".env")
	}

	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		slog.Debug("No .env file found (using environment variables or defaults)")
		return
	}

	slog.Info("Loading configuration from .env file", "path", envFile)
	if err := godotenv.Load(envFile); err != nil {
		slog.Warn("Failed to load .env file", "error", err)
	}
}
