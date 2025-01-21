package app

// AppConfig contains application configuration
type AppConfig struct {
	Host string `env:"APP_HOST" env-default:"localhost"`
	Port uint16 `env:"APP_PORT" env-default:"8080"`
}
