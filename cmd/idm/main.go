package main

import (
	"context"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/tendant/chi-demo/app"
	utils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/pkg/email"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/db"
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

type Config struct {
	IdmDbConfig IdmDbConfig
	AppConfig   app.AppConfig
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

	// Initialize email service
	emailConfig, err := email.LoadConfigFromEnv()
	if err != nil {
		slog.Error("Failed to load email config", "err", err)
		os.Exit(-1)
	}

	emailService, err := email.NewService(emailConfig)
	if err != nil {
		slog.Error("Failed to create email service", "err", err)
		os.Exit(-1)
	}

	iamQueries := iamdb.New(pool)
	iamService := iam.NewIamService(iamQueries)
	iamHandler := iam.NewHandle(iamService)
	iam.Routes(myApp.R, iamHandler)

	// Initialize login service with email
	loginQueries := db.New(pool)
	loginService := login.NewLoginService(loginQueries, emailService)
	loginHandler := login.NewHandle(loginService)
	login.Routes(myApp.R, loginHandler)

	myApp.Run()

}
