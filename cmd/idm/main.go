package main

import (
	"context"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/tendant/chi-demo/app"
	utils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/api"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
	"golang.org/x/exp/slog"
)

type IdmDbConfig struct {
	Host     string `env:"IDM_PG_HOST" env-default:"localhost"`
	Port     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	Database string `env:"IDM_PG_DATABASE" env-default:"idm_db"`
	User     string `env:"IDM_PG_USER" env-default:"idm"`
	Password string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
}

func (d IdmDbConfig) toDbConfig() utils.DbConfig {
	return utils.DbConfig{
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
}

type Config struct {
	IdmDbConfig IdmDbConfig
	AppConfig   app.AppConfig
	JwtConfig   JwtConfig
}

func main() {

	config := Config{}
	cleanenv.ReadEnv(&config)

	myApp := app.Default()
	app.RoutesHealthzReady(myApp.R)

	dbConfig := config.IdmDbConfig.toDbConfig()
	pool, err := utils.NewDbPool(context.Background(), dbConfig)
	if err != nil {
		slog.Error("Failed creating dbpool", "db", dbConfig.Database, "host", dbConfig.Host, "port", dbConfig.Port, "user", dbConfig.User)
		os.Exit(-1)
	}

	// iamQueries := iamdb.New(pool)
	// iamService := iam.NewIamService(iamQueries)
	// iamHandler := iam.NewHandle(iamService)
	// iam.Routes(myApp.R, iamHandler)

	// jwt service
	jwtService := auth.NewJwtServiceOptions(
		config.JwtConfig.JwtSecret,
		auth.WithCookieHttpOnly(config.JwtConfig.CookieHttpOnly),
		auth.WithCookieSecure(config.JwtConfig.CookieSecure),
	)

	// Initialize login service with email
	loginQueries := logindb.New(pool)
	loginRepository := login.NewPostgresLoginRepository(loginQueries)
	twofaQueries := twofadb.New(pool)
	loginService := login.NewLoginService(loginRepository, nil, nil, nil, nil)

	twoFaService := twofa.NewTwoFaService(twofaQueries, nil)

	loginHandler := api.NewHandle(loginService, *jwtService, api.WithTwoFactorService(twoFaService))
	myApp.R.Mount("/auth", api.Handler(loginHandler))

	myApp.Run()

}
