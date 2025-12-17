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
	"github.com/tendant/simple-idm/pkg/config"
	"github.com/tendant/simple-idm/pkg/device"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	"github.com/tendant/simple-idm/pkg/externalprovider"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	loginapi "github.com/tendant/simple-idm/pkg/login/loginapi"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/loginflow"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/role"
	"github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/tendant/simple-idm/pkg/signup"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
)

// Type aliases for backward compatibility - all configs now use pkg/config types
type (
	DatabaseConfig           = config.DatabaseConfig
	JWTConfig                = config.JWTConfig
	EmailConfig              = config.EmailConfig
	TwilioConfig             = config.TwilioConfig
	PasswordComplexityConfig = config.PasswordComplexityConfig
	LoginConfig              = config.LoginConfig
	ExternalProviderConfig   = config.ExternalProviderConfig
)

type Config struct {
	BaseUrl                  string `env:"BASE_URL" env-default:"http://localhost:3000"`
	DatabaseConfig           DatabaseConfig
	AppConfig                app.AppConfig
	JWTConfig                JWTConfig
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

	app.RegisterHealthzRoutes(server.R)

	dbConfig := config.DatabaseConfig.ToDbConfig()
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
	twofaRepo := twofa.NewPostgresTwoFARepository(twofaQueries)
	mapperQueries := mapperdb.New(pool)
	mapperRepo := mapper.NewPostgresMapperRepository(mapperQueries)

	// Initialize NotificationManager and register email notifier
	notificationManager, err := notification.NewNotificationManagerWithOptions(
		config.BaseUrl,
		notification.WithSMTP(notification.SMTPConfig{
			Host:     config.EmailConfig.Host,
			Port:     int(config.EmailConfig.Port),
			Username: config.EmailConfig.Username,
			Password: config.EmailConfig.Password,
			From:     config.EmailConfig.From,
			TLS:      config.EmailConfig.TLS,
		}),
		notification.WithTwilio(notification.TwilioConfig{
			TwilioAccountSid: config.TwilioConfig.TwilioAccountSid,
			TwilioAuthToken:  config.TwilioConfig.TwilioAuthToken,
			TwilioFrom:       config.TwilioConfig.TwilioFrom,
		}),
		notification.WithDefaultTemplates(),
	)
	if err != nil {
		slog.Error("Failed initialize notification manager", "err", err)
	}

	userMapper := mapper.NewDefaultUserMapper(mapperRepo)
	delegatedUserMapper := &mapper.DefaultDelegatedUserMapper{}

	// Create a password policy based on the environment
	passwordPolicy := config.PasswordComplexityConfig.ToPasswordPolicy()

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
		config.JWTConfig.Secret,
		config.JWTConfig.Issuer,
		config.JWTConfig.Audience,
	)

	tempTokenGenerator := tokengenerator.NewTempTokenGenerator(
		config.JWTConfig.Secret,
		config.JWTConfig.Issuer,
		config.JWTConfig.Audience,
	)

	tokenService := tokengenerator.NewDefaultTokenService(tokenGenerator, tokenGenerator, tempTokenGenerator, tokenGenerator, config.JWTConfig.Secret)
	tokenCookieService := tokengenerator.NewDefaultTokenCookieService(
		"/",
		config.JWTConfig.CookieHttpOnly,
		config.JWTConfig.CookieSecure,
		http.SameSiteLaxMode,
	)

	twoFaService := twofa.NewTwoFaService(
		twofaRepo,
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
	deviceService := device.NewDeviceService(deviceRepository)

	// Create LoginFlowService for orchestrated authentication flows
	loginFlowService := loginflow.NewLoginFlowService(
		loginService,
		twoFaService,
		deviceService,
		tokenService,
		&tokenCookieService,
		userMapper,
	)

	// Create a new handle with the LoginFlowService
	loginHandle := loginapi.NewHandle(
		loginapi.WithLoginService(loginService),
		loginapi.WithLoginFlowService(loginFlowService),
		loginapi.WithTokenCookieService(tokenCookieService),
		loginapi.WithResponseHandler(loginapi.NewDefaultResponseHandler()),
	)

	// Initialize IAM repository and service
	iamRepo := iam.NewPostgresIamRepository(iamQueries)
	iamService := iam.NewIamService(iamRepo)

	// Initialize role repository and service
	roleRepo := role.NewPostgresRoleRepository(roleQueries)
	roleService := role.NewRoleService(roleRepo)

	// Initialize logins management service
	loginsQueries := loginsdb.New(pool)
	loginsRepo := logins.NewPostgresLoginsRepository(loginsQueries)
	loginsServiceOptions := &logins.LoginsServiceOptions{
		PasswordManager: passwordManager,
	}
	loginsService := logins.NewLoginsService(loginsRepo, loginQueries, loginsServiceOptions)

	signupHandle := signup.NewHandleWithOptions(
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

	tokenAuth := jwtauth.New("HS256", []byte(config.JWTConfig.Secret), nil)

	server.R.Group(func(r chi.Router) {
		// Unified authentication middleware
		r.Use(client.AuthMiddleware(
			client.VerifierConfig{Name: "HMAC256", Auth: tokenAuth, Active: true},
		))
		r.Use(client.RequireAuth)

		// Device management routes
		deviceHandle := deviceapi.NewDeviceHandler(deviceService)
		r.Mount("/api/idm/device", deviceapi.Handler(deviceHandle))
	})

	server.Run()
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
