package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/sosodev/duration"
	"github.com/tendant/chi-demo/app"
	dbutils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/device"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	"github.com/tendant/simple-idm/pkg/externalprovider"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	loginapi "github.com/tendant/simple-idm/pkg/login/api"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/role"
	"github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/tendant/simple-idm/pkg/signup"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
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
	CookieSecure   bool   `env:"COOKIE_SECURE" env-default:"false"`
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
	BaseUrl                  string `env:"BASE_URL" env-default:"http://localhost:3000"`
	IdmDbConfig              IdmDbConfig
	AppConfig                app.AppConfig
	JwtConfig                JwtConfig
	EmailConfig              EmailConfig
	PasswordComplexityConfig PasswordComplexityConfig
	LoginConfig              LoginConfig
	TwilioConfig             TwilioConfig
	ExternalProviderConfig   ExternalProviderConfig
}

func main() {
	// Create a logger with source enabled
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true, // Enables line number & file path
	}))

	// Set the logger as the default
	slog.SetDefault(logger)

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
	passwordManager := login.NewPasswordManager(loginQueries)

	// Create a policy checker
	policyChecker := login.NewDefaultPasswordPolicyChecker(passwordPolicy, nil)
	passwordManager.WithPolicyChecker(policyChecker)

	// Create login service with the custom password manager
	loginRepository := login.NewPostgresLoginRepository(loginQueries)

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
		login.WithMagicLinkTokenExpiration(magicLinkExpiration.ToTimeDuration()),
	)
	slog.Info("Login service created", "maxFailedAttempts", config.LoginConfig.MaxFailedAttempts, "lockoutDuration", lockoutDuration.ToTimeDuration())

	// Create JWT token generator
	tokenGenerator := tokengenerator.NewJwtTokenGenerator(
		config.JwtConfig.JwtSecret,
		"simple-idm", // Issuer
		"simple-idm", // Audience
	)

	tempTokenGenerator := tokengenerator.NewTempTokenGenerator(
		config.JwtConfig.JwtSecret,
		"simple-idm", // Issuer
		"simple-idm", // Audience
	)

	tokenService := tokengenerator.NewDefaultTokenService(tokenGenerator, tokenGenerator, tempTokenGenerator, tokenGenerator, config.JwtConfig.Secret)
	tokenCookieService := tokengenerator.NewDefaultTokenCookieService(
		"/",
		config.JwtConfig.CookieHttpOnly,
		config.JwtConfig.CookieSecure,
		http.SameSiteLaxMode,
	)

	twoFaService := twofa.NewTwoFaService(
		twofaQueries,
		twofa.WithNotificationManager(notificationManager),
		twofa.WithUserMapper(userMapper),
	)

	// Initialize device service
	deviceExpirationDays := config.LoginConfig.DeviceExpirationDays
	var deviceExpiryDuration time.Duration
	isoDuration, err := duration.Parse(deviceExpirationDays)
	if err != nil {
		slog.Error("Failed to parse device expiration duration", "error", err)
		deviceExpiryDuration = device.DefaultDeviceExpiryDuration
	} else {
		deviceExpiryDuration = isoDuration.ToTimeDuration()
		slog.Info("Device expiration duration set", "duration", deviceExpiryDuration)
	}

	deviceRepositoryOptions := device.DeviceRepositoryOptions{
		ExpiryDuration: deviceExpiryDuration,
	}
	deviceRepository := device.NewPostgresDeviceRepositoryWithOptions(pool, deviceRepositoryOptions)
	deviceService := device.NewDeviceService(deviceRepository, loginRepository)

	// Create a new handle with the domain login service directly
	loginHandle := loginapi.NewHandle(
		loginapi.WithLoginService(loginService),
		loginapi.WithTokenService(tokenService),
		loginapi.WithTokenCookieService(tokenCookieService),
		loginapi.WithUserMapper(userMapper),
		loginapi.WithDeviceService(*deviceService),
		loginapi.WithTwoFactorService(twoFaService),
		loginapi.WithResponseHandler(loginapi.NewDefaultResponseHandler()),
		loginapi.WithDeviceExpirationDays(deviceExpiryDuration),
	)

	// Initialize IAM repository and service
	iamRepo := iam.NewPostgresIamRepository(iamQueries)
	iamService := iam.NewIamService(iamRepo)

	// Initialize role repository and service
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	roleService := role.NewRoleService(roleRepo)

	// Initialize logins management service
	loginsQueries := loginsdb.New(pool)
	loginsServiceOptions := &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	}
	loginsService := logins.NewLoginsService(loginsQueries, loginQueries, loginsServiceOptions)

	signupHandle := signup.NewHandle(
		signup.WithIamService(*iamService),
		signup.WithRoleService(*roleService),
		signup.WithLoginsService(*loginsService),
		signup.WithRegistrationEnabled(config.LoginConfig.RegistrationEnabled),
		signup.WithDefaultRole(config.LoginConfig.RegistrationDefaultRole),
		signup.WithLoginService(*loginService),
	)

	// Initialize External Provider repository and service
	externalProviderRepository := externalprovider.NewInMemoryExternalProviderRepository()

	// Configure external providers based on environment variables
	setupExternalProviders(externalProviderRepository, &config.ExternalProviderConfig)

	// Create external provider service
	slog.Info("Configuring external provider service",
		"user_creation_enabled", true,
		"auto_user_creation", true,
		"default_role", config.ExternalProviderConfig.DefaultRole)

	externalProviderService := externalprovider.NewExternalProviderService(
		externalProviderRepository,
		loginService,
		userMapper,
		externalprovider.WithBaseURL("http://localhost:4000"),
		externalprovider.WithStateExpiration(10*time.Minute),
		externalprovider.WithHTTPClient(&http.Client{}),
		externalprovider.WithNotificationManager(notificationManager),
		externalprovider.WithUserCreationEnabled(true),
		externalprovider.WithAutoUserCreation(true),
		externalprovider.WithLoginsService(loginsService),
		externalprovider.WithIamService(iamService),
		externalprovider.WithRoleService(roleService),
		externalprovider.WithDefaultRole(config.ExternalProviderConfig.DefaultRole),
	)

	// Create external provider API handler
	externalProviderHandle := externalProviderAPI.NewHandle(
		externalProviderService,
		loginService,
		tokenService,
		tokenCookieService,
	).WithFrontendURL(config.BaseUrl)

	slog.Info("Registration enabled", "enabled", config.LoginConfig.RegistrationEnabled)

	// Mount only specific auth endpoints
	server.R.Route("/api/idm/auth", func(r chi.Router) {
		// Magic link endpoints
		r.Post("/login/magic-link/email", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.InitiateMagicLinkLoginByEmail(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
		r.Get("/login/magic-link/validate", func(w http.ResponseWriter, r *http.Request) {
			params := loginapi.ValidateMagicLinkTokenParams{
				Token: r.URL.Query().Get("token"),
			}
			resp := loginHandle.ValidateMagicLinkToken(w, r, params)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})

		// 2FA endpoints (needed for magic link flow)
		r.Post("/2fa/send", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.Post2faSend(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
		r.Post("/2fa/validate", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.Post2faValidate(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})

		// Token refresh endpoint
		r.Post("/token/refresh", func(w http.ResponseWriter, r *http.Request) {
			resp := loginHandle.PostTokenRefresh(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
	})

	// Mount only passwordless signup endpoint
	server.R.Route("/api/idm/signup", func(r chi.Router) {
		r.Post("/passwordless", func(w http.ResponseWriter, r *http.Request) {
			resp := signupHandle.RegisterUserPasswordless(w, r)
			if resp != nil {
				render.Render(w, r, resp)
			}
		})
	})

	// Mount external provider endpoints (public, no authentication required)
	server.R.Mount("/api/idm/external", externalProviderAPI.Handler(externalProviderHandle))

	tokenAuth := jwtauth.New("HS256", []byte(config.JwtConfig.JwtSecret), nil)

	server.R.Group(func(r chi.Router) {
		r.Use(client.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator(tokenAuth))
		r.Use(client.AuthUserMiddleware)

		// Device management routes
		deviceHandle := deviceapi.NewDeviceHandler(deviceService)
		r.Mount("/api/idm/device", deviceapi.Handler(deviceHandle))
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
func setupExternalProviders(repository externalprovider.ExternalProviderRepository, config *ExternalProviderConfig) {
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

		err := repository.CreateProvider(googleProvider)
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

		err := repository.CreateProvider(microsoftProvider)
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

		err := repository.CreateProvider(githubProvider)
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

		err := repository.CreateProvider(linkedinProvider)
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
