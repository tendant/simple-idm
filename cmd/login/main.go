package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/jinzhu/copier"
	"github.com/tendant/chi-demo/app"
	dbutils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/auth"
	authpkg "github.com/tendant/simple-idm/pkg/auth"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/impersonate"
	"github.com/tendant/simple-idm/pkg/impersonate/impersonatedb"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/profile"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"github.com/tendant/simple-idm/pkg/role"
	"github.com/tendant/simple-idm/pkg/role/roledb"
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

type JwtConfig struct {
	JwtSecret      string `env:"JWT_SECRET" env-default:"very-secure-jwt-secret"`
	CookieHttpOnly bool   `env:"COOKIE_HTTP_ONLY" env-default:"true"`
	CookieSecure   bool   `env:"COOKIE_SECURE" env-default:"false"`
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

type EmailConfig struct {
	Host     string `env:"EMAIL_HOST" env-default:"localhost"`
	Port     uint16 `env:"EMAIL_PORT" env-default:"1025"`
	Username string `env:"EMAIL_USERNAME" env-default:"noreply@example.com"`
	Password string `env:"EMAIL_PASSWORD" env-default:"pwd"`
	From     string `env:"EMAIL_FROM" env-default:"noreply@example.com"`
}

type PasswordComplexityConfig struct {
	RequiredDigit           bool `env:"PASSWORD_COMPLEXITY_REQUIRE_DIGIT" env-default:"true"`
	RequiredLowercase       bool `env:"PASSWORD_COMPLEXITY_REQUIRE_LOWERCASE" env-default:"true"`
	RequiredNonAlphanumeric bool `env:"PASSWORD_COMPLEXITY_REQUIRE_NON_ALPHANUMERIC" env-default:"true"`
	RequiredUppercase       bool `env:"PASSWORD_COMPLEXITY_REQUIRE_UPPERCASE" env-default:"true"`
	RequiredLength          int  `env:"PASSWORD_COMPLEXITY_REQUIRED_LENGTH" env-default:"8"`
}

type Config struct {
	BaseUrl                  string `env:"BASE_URL" env-default:"http://localhost:3000"`
	IdmDbConfig              IdmDbConfig
	AppConfig                app.AppConfig
	JwtConfig                JwtConfig
	EmailConfig              EmailConfig
	PasswordComplexityConfig PasswordComplexityConfig
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
	impersonateQueries := impersonatedb.New(pool)
	twofaQueries := twofadb.New(pool)

	// Initialize NotificationManager and register email notifier
	notificationManager, err := notice.NewNotificationManager(config.BaseUrl, notification.SMTPConfig{
		Host:     config.EmailConfig.Host,
		Port:     int(config.EmailConfig.Port),
		Username: config.EmailConfig.Username,
		Password: config.EmailConfig.Password,
		From:     config.EmailConfig.From,
		NoTLS:    true,
	})
	if err != nil {
		slog.Error("Failed initialize notification manager", "err", err)
	}

	userMapper := login.NewDefaultUserMapper(loginQueries)
	delegatedUserMapper := &login.DefaultDelegatedUserMapper{}
	loginService := login.NewLoginService(loginQueries, notificationManager, userMapper, delegatedUserMapper)

	// jwt service
	jwtService := auth.NewJwtServiceOptions(
		config.JwtConfig.JwtSecret,
		auth.WithCookieHttpOnly(config.JwtConfig.CookieHttpOnly),
		auth.WithCookieSecure(config.JwtConfig.CookieSecure),
	)

	// auth queries
	// authQueries := authDb.New(pool)

	// auth login service
	var pwdComplex authpkg.PasswordComplexity
	copier.Copy(&pwdComplex, &config.PasswordComplexityConfig)
	// authLoginService := authpkg.NewAuthLoginService(
	// 	authQueries,
	// 	authpkg.WithPwdComplex(pwdComplex),
	// )

	twoFaService := twofa.NewTwoFaService(twofaQueries, notificationManager)
	loginHandle := login.NewHandle(loginService, *jwtService, login.WithTwoFactorService(twoFaService))

	// authHandle := authpkg.NewHandle(*jwtService, authLoginService)

	server.R.Mount("/auth", login.Handler(loginHandle))

	tokenAuth := jwtauth.New("HS256", []byte(config.JwtConfig.JwtSecret), nil)

	server.R.Group(func(r chi.Router) {
		r.Use(login.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator(tokenAuth))
		r.Use(login.AuthUserMiddleware)
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
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
		profileService := profile.NewProfileService(profileQueries)
		profileHandle := profile.NewHandle(profileService)
		r.Mount("/profile", profile.Handler(profileHandle))

		// r.Mount("/auth", authpkg.Handler(authHandle))
		// Initialize user service and handle
		iamService := iam.NewIamService(iamQueries)
		userHandle := iam.NewHandle(iamService)
		r.Mount("/idm", iam.Handler(userHandle))

		// Initialize role service and routes
		roleService := role.NewRoleService(roleQueries)
		roleHandle := role.NewHandle(roleService)
		r.Mount("/idm/roles", role.Handler(roleHandle))

		// Initialize impersonate service and routes
		impersonateService := impersonate.NewImpersonateService(impersonateQueries)
		impersonateHandle := impersonate.NewHandle(impersonateService, *jwtService)
		r.Mount("/idm/impersonate", impersonate.Handler(impersonateHandle))

		// Initialize two factor authentication service and routes
		twoFaHandle := twofa.NewHandle(twoFaService)
		r.Mount("/idm/twofa", twofa.Handler(twoFaHandle))
	})

	app.RoutesHealthzReady(server.R)
	server.Run()

}
