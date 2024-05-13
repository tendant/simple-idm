package main

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tendant/chi-demo/app"
	"github.com/tendant/simple-user/user/db"
	"golang.org/x/exp/slog"
)

type DbConfig struct {
	Host     string
	Port     uint16
	Database string
	User     string
	Password string
}

func (c DbConfig) toDatabaseUrl() string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.User, c.Password),
		Host:   fmt.Sprintf("%s:%d", c.Host, c.Port),
		Path:   c.Database,
	}
	return u.String()
}

type DbConf interface {
	toDbConfig() DbConfig
}

type IdmDbConfig struct {
	Host     string `env:"IDM_PG_HOST" env-default:"localhost"`
	Port     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	Database string `env:"IDM_PG_DATABASE" env-default:"idm_db"`
	User     string `env:"IDM_PG_USER" env-default:"idm"`
	Password string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
}

func (d IdmDbConfig) toDbConfig() DbConfig {
	return DbConfig{
		Host:     d.Host,
		Port:     d.Port,
		Database: d.Database,
		User:     d.User,
		Password: d.Password,
	}
}

func main() {
	myApp := app.Default()
	Routes(myApp.R)

	pool, err := pgxpool.New(context.Background(), cfg.DemoDb.toDbConfig().toDatabaseUrl())
	if err != nil {
		slog.Error("Failed creating dbpool", "db", cfg.DemoDb.Database, "url", cfg.DemoDb.toDbConfig().toDatabaseUrl())
		os.Exit(-1)
	} else {
		queries := db.New(pool)
		userService := UserService{
			queries: queries,
		}
		handler := Handler{
			UserService: userService,
		}
		handler.Routes(myApp.R)
	}

	myApp.Run()

}
