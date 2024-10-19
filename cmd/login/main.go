package main

import (
	"context"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/tendant/chi-demo/app"
	utils "github.com/tendant/db-utils/db"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/login"
	"github.com/tendant/simple-idm/login/db"
	"golang.org/x/exp/slog"
)

type IdmDbConfig struct {
	Host     string `env:"IDM_PG_HOST" env-default:"localhost"`
	Port     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	Database string `env:"IDM_PG_DATABASE" env-default:"idm_db"`
	User     string `env:"IDM_PG_USER" env-default:"idm"`
	Password string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
}

type JwtConfig struct {
	JwtSecret string `env:"JWT_SECRET" env-default:"very-secure-jwt-secret"`
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
	JwtConfig   JwtConfig
}

func main() {

	config := Config{}
	cleanenv.ReadEnv(&config)

	server := app.DefaultApp()

	app.RoutesHealthz(server.R)
	app.RoutesHealthzReady(server.R)

	dbConfig := config.IdmDbConfig.toDbConfig()
	pool, err := utils.NewDbPool(context.Background(), dbConfig)
	if err != nil {
		slog.Error("Failed creating dbpool", "db", dbConfig.Database, "host", dbConfig.Host, "port", dbConfig.Port, "user", dbConfig.User)
		os.Exit(-1)
	}

	queries := db.New(pool)
	loginService := login.New(queries)

	// jwt service
	jwtService := auth.Jwt{Secret: config.JwtConfig.JwtSecret}

	loginHandle := login.NewHandle(loginService, jwtService)

	server.R.Mount("/", login.Handler(loginHandle))

	server.R.Group(func(r chi.Router) {
		r.Use(login.AuthUserMiddleware)
		r.Get("/private", func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, http.StatusText(http.StatusOK))
		})
	})

	server.Run()

}
