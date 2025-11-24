package router

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tendant/simple-idm/pkg/client"
	pkgconfig "github.com/tendant/simple-idm/pkg/config"
	"github.com/tendant/simple-idm/pkg/device"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	"github.com/tendant/simple-idm/pkg/emailverification"
	emailverificationapi "github.com/tendant/simple-idm/pkg/emailverification/api"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	"github.com/tendant/simple-idm/pkg/iam"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	iamdb "github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	loginapi "github.com/tendant/simple-idm/pkg/login/api"
	logindb "github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/logins"
	loginsdb "github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	mapperdb "github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	oauth2clientapi "github.com/tendant/simple-idm/pkg/oauth2client/api"
	"github.com/tendant/simple-idm/pkg/oidc"
	oidcapi "github.com/tendant/simple-idm/pkg/oidc/api"
	profileapi "github.com/tendant/simple-idm/pkg/profile/api"
	"github.com/tendant/simple-idm/pkg/role"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	roledb "github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/tendant/simple-idm/pkg/loginflow"
	loginv2 "github.com/tendant/simple-idm/pkg/login/handler/v2"
	"github.com/tendant/simple-idm/pkg/signup"
	signupv2 "github.com/tendant/simple-idm/pkg/signup/handler/v2"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	twofaapi "github.com/tendant/simple-idm/pkg/twofa/api"
	"github.com/tendant/simple-idm/pkg/wellknown"
)

// MinimalOptions contains minimal configuration for Simple IDM integration
type MinimalOptions struct {
	// Required
	DatabaseURL string // PostgreSQL connection string
	JWTSecret   string // JWT signing secret (use strong random string in production)
	BaseURL     string // Base URL of the application (e.g., "http://localhost:8000")

	// Optional - defaults will be used if not provided
	PrefixConfig        *pkgconfig.PrefixConfig // API route prefixes
	RegistrationEnabled bool                    // Allow user registration (default: true)
	DefaultRole         string                  // Default role for new users (default: "user")
	JWTIssuer           string                  // JWT token issuer claim (default: BaseURL)
	JWTAudience         string                  // JWT token audience claim (default: BaseURL)
	AccessTokenExpiry   string                  // Access token expiration duration (e.g., "30m", default: "5m")
	RefreshTokenExpiry  string                  // Refresh token expiration duration (e.g., "48h", default: "15m")
}

// NewMinimalConfig creates a Simple IDM router configuration with sane defaults
// This is the easiest way to integrate Simple IDM into your application
//
// Example:
//
//	cfg, err := router.NewMinimalConfig(router.MinimalOptions{
//	    DatabaseURL: "postgres://user:pwd@localhost:5432/mydb?sslmode=disable",
//	    JWTSecret:   "your-secret-key",
//	    BaseURL:     "http://localhost:8000",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	router.SetupRoutes(r, cfg)
func NewMinimalConfig(opts MinimalOptions) (Config, error) {
	// 1. Initialize database pool
	pgConfig, err := pgxpool.ParseConfig(opts.DatabaseURL)
	if err != nil {
		return Config{}, err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), pgConfig)
	if err != nil {
		return Config{}, err
	}

	// 2. Initialize core services
	loginQueries := logindb.New(pool)
	loginRepo := login.NewPostgresLoginRepository(loginQueries)
	passwordManager := login.NewPasswordManager(loginQueries)

	// Initialize mapper for user lookup
	mapperQueries := mapperdb.New(pool)
	mapperRepo := mapper.NewPostgresMapperRepository(mapperQueries)
	userMapper := mapper.NewDefaultUserMapper(mapperRepo)

	// Notification manager - read from environment variables
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = opts.BaseURL
	}
	emailPort, _ := strconv.Atoi(os.Getenv("EMAIL_PORT"))
	emailTLS := os.Getenv("EMAIL_TLS") == "true"

	notificationManager, _ := notice.NewNotificationManager(
		frontendURL,
		notice.WithSMTP(notification.SMTPConfig{
			Host:     os.Getenv("EMAIL_HOST"),
			Port:     emailPort,
			Username: os.Getenv("EMAIL_USERNAME"),
			Password: os.Getenv("EMAIL_PASSWORD"),
			From:     os.Getenv("EMAIL_FROM"),
			TLS:      emailTLS,
		}),
		notice.WithDefaultTemplates(),
	)

	loginService := login.NewLoginServiceWithOptions(
		loginRepo,
		login.WithPasswordManager(passwordManager),
		login.WithUserMapper(userMapper),
		login.WithNotificationManager(notificationManager),
	)

	// IAM service
	iamQueries := iamdb.New(pool)
	iamRepo := iam.NewPostgresIamRepository(iamQueries)
	iamService := iam.NewIamService(iamRepo)

	// Role service
	roleQueries := roledb.New(pool)
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	roleService := role.NewRoleService(roleRepo)

	// Device service
	deviceRepo := device.NewPostgresDeviceRepository(pool)
	deviceService := device.NewDeviceService(deviceRepo)

	// Determine JWT issuer and audience (use BaseURL as default)
	jwtIssuer := opts.JWTIssuer
	if jwtIssuer == "" {
		jwtIssuer = opts.BaseURL
	}
	jwtAudience := opts.JWTAudience
	if jwtAudience == "" {
		jwtAudience = opts.BaseURL
	}

	// Token services
	hmacTokenGenerator := tokengenerator.NewJwtTokenGenerator(opts.JWTSecret, jwtIssuer, jwtAudience)
	tempTokenGenerator := tokengenerator.NewTempTokenGenerator(opts.JWTSecret, jwtIssuer, jwtAudience)

	// Configure token expiry from options
	tokenOptions := []tokengenerator.Option{
		tokengenerator.WithTempTokenGenerator(tempTokenGenerator),
	}
	if opts.AccessTokenExpiry != "" {
		tokenOptions = append(tokenOptions, tokengenerator.WithAccessTokenExpiry(opts.AccessTokenExpiry))
	}
	if opts.RefreshTokenExpiry != "" {
		tokenOptions = append(tokenOptions, tokengenerator.WithRefreshTokenExpiry(opts.RefreshTokenExpiry))
	}

	tokenService := tokengenerator.NewTokenServiceFromGenerator(
		hmacTokenGenerator,
		tokenOptions...,
	)
	tokenCookieService := tokengenerator.NewDefaultTokenCookieService(
		"/",
		true,  // httpOnly
		false, // secure (false for development, true for production)
		http.SameSiteLaxMode,
	)

	// Two-factor service (no-op for minimal config)
	twoFaService := twofa.NewNoOpTwoFactorService()

	// Logins service
	loginsQueries := loginsdb.New(pool)
	loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)
	loginsServiceOptions := &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	}
	loginsService := logins.NewLoginsService(loginsRepo, loginQueries, loginsServiceOptions)

	// Email verification service
	emailVerificationRepo := emailverification.NewPostgresEmailVerificationRepository(pool)
	tokenExpiry := 24 * time.Hour
	if expiryEnv := os.Getenv("EMAIL_VERIFICATION_TOKEN_EXPIRY"); expiryEnv != "" {
		if parsed, err := time.ParseDuration(expiryEnv); err == nil {
			tokenExpiry = parsed
		}
	}
	resendWindow := 1 * time.Hour
	if windowEnv := os.Getenv("EMAIL_VERIFICATION_RESEND_WINDOW"); windowEnv != "" {
		if parsed, err := time.ParseDuration(windowEnv); err == nil {
			resendWindow = parsed
		}
	}
	emailVerificationService := emailverification.NewEmailVerificationService(
		emailVerificationRepo,
		notificationManager,
		frontendURL,
		emailverification.WithTokenExpiry(tokenExpiry),
		emailverification.WithResendLimit(3),
		emailverification.WithResendWindow(resendWindow),
	)

	// 3. Create JWT authenticators
	// Using HMAC256 for simplicity (production should use RSA256)
	rsaAuth := jwtauth.New("HS256", []byte(opts.JWTSecret), nil)
	hmacAuth := jwtauth.New("HS256", []byte(opts.JWTSecret), nil)

	// 4. Configure prefixes (use provided or defaults)
	prefixConfig := opts.PrefixConfig
	if prefixConfig == nil {
		// Use v2 API prefixes as default for new applications
		defaultV2 := pkgconfig.DefaultV2Prefixes()
		prefixConfig = &defaultV2
	}

	// Default values
	registrationEnabled := opts.RegistrationEnabled
	if !registrationEnabled {
		registrationEnabled = true // Default to enabled
	}
	defaultRole := opts.DefaultRole
	if defaultRole == "" {
		defaultRole = "user"
	}

	// 5. Create handlers
	loginHandle := loginapi.NewHandle(
		loginapi.WithLoginService(loginService),
		loginapi.WithTokenService(tokenService),
		loginapi.WithTokenCookieService(tokenCookieService),
		loginapi.WithTwoFactorService(twoFaService),
		loginapi.WithDeviceService(*deviceService),
	)

	signupHandle := signup.NewHandleWithOptions(
		signup.WithIamService(*iamService),
		signup.WithRoleService(*roleService),
		signup.WithLoginsService(*loginsService),
		signup.WithRegistrationEnabled(registrationEnabled),
		signup.WithDefaultRole(defaultRole),
		signup.WithLoginService(*loginService),
		signup.WithEmailVerificationService(emailVerificationService),
	)

	userHandle := iamapi.NewHandle(iamService)

	// OAuth2 client service (environment-based, minimal config)
	oauth2Repo, _ := oauth2client.NewEnvOAuth2ClientRepository() // Ignore error for minimal config
	oauth2ClientService := oauth2client.NewClientService(oauth2Repo)

	// OIDC service (in-memory repository for minimal config)
	oidcRepository := oidc.NewInMemoryOIDCRepository()
	oidcService := oidc.NewOIDCServiceWithOptions(
		oidcRepository,
		oauth2ClientService,
		oidc.WithTokenGenerator(hmacTokenGenerator),
		oidc.WithBaseURL(opts.BaseURL),
		oidc.WithUserMapper(userMapper),
		oidc.WithIssuer(jwtIssuer),
	)

	// OIDC handle
	oidcHandle := oidcapi.NewOidcHandle(oauth2ClientService, oidcService)
	emptyExternalProviderHandle := &externalProviderAPI.Handle{}
	emptyEmailVerificationHandle := emailverificationapi.Handler{}
	emptyProfileHandle := profileapi.Handle{}
	roleHandle := &roleapi.Handle{}
	emptyTwoFaHandle := &twofaapi.Handle{}
	emptyDeviceHandle := &deviceapi.DeviceHandler{}
	loginsHandle := &logins.LoginsHandle{}
	emptyOAuth2ClientHandle := &oauth2clientapi.Handle{}

	// Signup service (needed for signupHandlerV2)
	signupService := signup.NewSignupService(
		signup.WithIamServiceForSignup(iamService),
		signup.WithRoleServiceForSignup(roleService),
		signup.WithLoginServiceForSignup(loginService),
		signup.WithLoginsServiceForSignup(loginsService),
		signup.WithRegistrationEnabledForSignup(registrationEnabled),
		signup.WithDefaultRoleForSignup(defaultRole),
	)

	// Login flow service (needed for v2 handlers)
	loginFlowService := loginflow.NewLoginFlowService(
		loginService,
		twoFaService,
		deviceService,
		tokenService,
		&tokenCookieService,
		userMapper,
	)

	// V2 handlers (optional - applications can use these for v2 route support)
	loginHandlerV2 := loginv2.NewHandle(
		loginService,
		loginFlowService,
		tokenCookieService,
	)
	signupHandlerV2 := signupv2.NewHandle(
		signupService,
		loginFlowService,
		tokenCookieService,
	)

	// Well-known configuration
	wellKnownConfig := wellknown.Config{
		ResourceURI:            opts.BaseURL,
		AuthorizationServerURI: opts.BaseURL,
		BaseURL:                opts.BaseURL,
		Scopes:                 []string{"openid", "profile", "email", "groups"},
		ResourceDocumentation:  opts.BaseURL + "/docs",
	}
	wellKnownHandler := *wellknown.NewHandler(wellKnownConfig)

	// 6. Return complete configuration
	return Config{
		PrefixConfig: *prefixConfig,

		// Fully functional handlers
		LoginHandle:  loginHandle,
		SignupHandle: *signupHandle,
		UserHandle:   userHandle,
		LoginsHandle: loginsHandle,

		// Minimal/empty handlers (routes registered but may not be fully functional)
		OIDCHandle:              oidcHandle,
		ExternalProviderHandle:  emptyExternalProviderHandle,
		EmailVerificationHandle: emptyEmailVerificationHandle,
		ProfileHandle:           emptyProfileHandle,
		RoleHandle:              roleHandle,
		TwoFaHandle:             emptyTwoFaHandle,
		DeviceHandle:            emptyDeviceHandle,
		OAuth2ClientHandle:      emptyOAuth2ClientHandle,

		WellKnownHandler: wellKnownHandler,

		RSAAuth:  rsaAuth,
		HMACAuth: hmacAuth,

		GetMeFunc: func(r *http.Request) (interface{}, error) {
			authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
			if !ok {
				return nil, http.ErrNoCookie
			}
			return loginService.GetMe(r.Context(), authUser.UserUuid)
		},

		SessionEnabled: false,
		SessionHandle:  nil,

		// V2 handlers for applications that want to use v2 routes
		V2: V2Config{
			LoginHandlerV2:  loginHandlerV2,
			SignupHandlerV2: signupHandlerV2,
		},
	}, nil
}
