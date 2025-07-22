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
	"github.com/tendant/chi-demo/app"
	dbutils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/iam"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/signup"

	// "github.com/tendant/simple-idm/pkg/impersonate/impersonatedb"

	"github.com/sosodev/duration"
	"github.com/tendant/simple-idm/pkg/device"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	"github.com/tendant/simple-idm/pkg/login"
	loginapi "github.com/tendant/simple-idm/pkg/login/api"
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

type Config struct {
	BaseUrl                  string `env:"BASE_URL" env-default:"http://localhost:3000"`
	IdmDbConfig              IdmDbConfig
	AppConfig                app.AppConfig
	JwtConfig                JwtConfig
	EmailConfig              EmailConfig
	PasswordComplexityConfig PasswordComplexityConfig
	LoginConfig              LoginConfig
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
	notificationManager, err := notice.NewNotificationManager(config.BaseUrl, notification.SMTPConfig{
		Host:     config.EmailConfig.Host,
		Port:     int(config.EmailConfig.Port),
		Username: config.EmailConfig.Username,
		Password: config.EmailConfig.Password,
		From:     config.EmailConfig.From,
		TLS:      config.EmailConfig.TLS,
	})
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
	loginsHandle := logins.NewHandle(loginsService, twoFaService)

	signupHandle := signup.NewHandle(
		signup.WithIamService(*iamService),
		signup.WithRoleService(*roleService),
		signup.WithLoginsService(*loginsService),
		signup.WithRegistrationEnabled(config.LoginConfig.RegistrationEnabled),
		signup.WithDefaultRole(config.LoginConfig.RegistrationDefaultRole),
		signup.WithLoginService(*loginService),
	)

	slog.Info("Registration enabled", "enabled", config.LoginConfig.RegistrationEnabled)
	server.R.Mount("/api/idm/auth", loginapi.Handler(loginHandle))
	server.R.Mount("/api/idm/signup", signup.Handler(signupHandle))

	tokenAuth := jwtauth.New("HS256", []byte(config.JwtConfig.JwtSecret), nil)

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
		profileHandle := profileapi.NewHandle(profileService, twoFaService, tokenService, tokenCookieService, loginService, deviceService, responseHandler)
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
		r.Mount("/idm/logins", loginsRouter)

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
