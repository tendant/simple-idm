package config

import (
	"fmt"

	dbutils "github.com/tendant/db-utils/db"
)

// DatabaseConfig holds PostgreSQL database configuration
// This is shared across all services to avoid duplication
type DatabaseConfig struct {
	Host     string `env:"IDM_PG_HOST" env-default:"localhost"`
	Port     uint16 `env:"IDM_PG_PORT" env-default:"5432"`
	Database string `env:"IDM_PG_DATABASE" env-default:"idm_db"`
	User     string `env:"IDM_PG_USER" env-default:"idm"`
	Password string `env:"IDM_PG_PASSWORD" env-default:"pwd"`
	Schema   string `env:"IDM_PG_SCHEMA" env-default:"public"`
}

// ToDatabaseURL converts the config to a PostgreSQL connection URL
func (d DatabaseConfig) ToDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&search_path=%s,public",
		d.User, d.Password, d.Host, d.Port, d.Database, d.Schema)
}

// ToDbConfig converts the config to a db-utils DbConfig
func (d DatabaseConfig) ToDbConfig() dbutils.DbConfig {
	return dbutils.DbConfig{
		Host:     d.Host,
		Port:     d.Port,
		Database: d.Database,
		User:     d.User,
		Password: d.Password,
	}
}

// NewDatabaseConfigFromEnv creates a DatabaseConfig from environment variables
func NewDatabaseConfigFromEnv() DatabaseConfig {
	return DatabaseConfig{
		Host:     GetEnvOrDefault("IDM_PG_HOST", "localhost"),
		Port:     GetEnvUint16("IDM_PG_PORT", 5432),
		Database: GetEnvOrDefault("IDM_PG_DATABASE", "idm_db"),
		User:     GetEnvOrDefault("IDM_PG_USER", "idm"),
		Password: GetEnvOrDefault("IDM_PG_PASSWORD", "pwd"),
		Schema:   GetEnvOrDefault("IDM_PG_SCHEMA", "public"),
	}
}
