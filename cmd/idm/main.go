package main

import (
	"context"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/tendant/chi-demo/app"
	utils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-user/handler"
	"github.com/tendant/simple-user/user"
	"github.com/tendant/simple-user/user/db"
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

func main() {
	myApp := app.Default()

	idmDbConfig := IdmDbConfig{}
	cleanenv.ReadEnv(&idmDbConfig)
	dbConfig := idmDbConfig.toDbConfig()

	slog.Debug("db pool url **********:", "url", dbConfig)
	pool, err := utils.NewDbPool(context.Background(), dbConfig)
	if err != nil {
		slog.Error("Failed creating dbpool", "db", dbConfig.Database, "host", dbConfig.Host, "port", dbConfig.Port, "user", dbConfig.User)
		os.Exit(-1)
	} else {
		queries := db.New(pool)
		userService := user.New(queries)
		handler := handler.Handler{
			UserService: userService,
		}
		handler.Routes(myApp.R)
	}

	myApp.Run()

}
