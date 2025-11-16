package router

import (
	"context"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tendant/simple-idm/pkg/client"
	pkgconfig "github.com/tendant/simple-idm/pkg/config"
	"github.com/tendant/simple-idm/pkg/device"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	emailverificationapi "github.com/tendant/simple-idm/pkg/emailverification/api"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	"github.com/tendant/simple-idm/pkg/iam"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	iamdb "github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	loginapi "github.com/tendant/simple-idm/pkg/login/api"
	logindb "github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	loginsdb "github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	mapperdb "github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	oauth2clientapi "github.com/tendant/simple-idm/pkg/oauth2client/api"
	oidcapi "github.com/tendant/simple-idm/pkg/oidc/api"
	profileapi "github.com/tendant/simple-idm/pkg/profile/api"
	"github.com/tendant/simple-idm/pkg/role"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	roledb "github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/tendant/simple-idm/pkg/signup"
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

	loginService := login.NewLoginServiceWithOptions(
		loginRepo,
		login.WithPasswordManager(passwordManager),
		login.WithUserMapper(userMapper),
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

	// Token services
	hmacTokenGenerator := tokengenerator.NewJwtTokenGenerator(opts.JWTSecret, opts.BaseURL, opts.BaseURL)
	tempTokenGenerator := tokengenerator.NewTempTokenGenerator(opts.JWTSecret, opts.BaseURL, opts.BaseURL)
	tokenService := tokengenerator.NewTokenServiceFromGenerator(
		hmacTokenGenerator,
		tokengenerator.WithTempTokenGenerator(tempTokenGenerator),
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

	// 3. Create JWT authenticators
	// Using HMAC256 for simplicity (production should use RSA256)
	rsaAuth := jwtauth.New("HS256", []byte(opts.JWTSecret), nil)
	hmacAuth := jwtauth.New("HS256", []byte(opts.JWTSecret), nil)

	// 4. Configure prefixes (use provided or defaults)
	prefixConfig := opts.PrefixConfig
	if prefixConfig == nil {
		prefixConfig = &pkgconfig.PrefixConfig{
			Auth:          "/api/v1/idm/auth",
			Signup:        "/api/v1/idm/signup",
			Profile:       "/api/v1/idm/profile",
			TwoFA:         "/api/v1/idm/2fa",
			Email:         "/api/v1/idm/email",
			OAuth2:        "/api/v1/idm/oauth2",
			Users:         "/api/v1/idm/users",
			Roles:         "/api/v1/idm/roles",
			Device:        "/api/v1/idm/device",
			Logins:        "/api/v1/idm/logins",
			OAuth2Clients: "/api/v1/idm/oauth2-clients",
			External:      "/api/v1/idm/external",
		}
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
	)

	userHandle := iamapi.NewHandle(iamService)

	// Empty handlers for optional features
	emptyOIDCHandle := &oidcapi.OidcHandle{}
	emptyExternalProviderHandle := &externalProviderAPI.Handle{}
	emptyEmailVerificationHandle := emailverificationapi.Handler{}
	emptyProfileHandle := profileapi.Handle{}
	roleHandle := &roleapi.Handle{}
	emptyTwoFaHandle := &twofaapi.Handle{}
	emptyDeviceHandle := &deviceapi.DeviceHandler{}
	loginsHandle := &logins.LoginsHandle{}
	emptyOAuth2ClientHandle := &oauth2clientapi.Handle{}

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
		OIDCHandle:              emptyOIDCHandle,
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
	}, nil
}
