package config

import (
	"net/http"
	"time"

	"github.com/sosodev/duration"
)

// JWTConfig holds JWT authentication configuration
// This is shared across all services to avoid duplication
type JWTConfig struct {
	Secret             string `env:"JWT_SECRET" env-default:"very-secure-jwt-secret"`
	CookieHttpOnly     bool   `env:"COOKIE_HTTP_ONLY" env-default:"true"`
	CookieSecure       bool   `env:"COOKIE_SECURE" env-default:"true"`
	AccessTokenExpiry  string `env:"ACCESS_TOKEN_EXPIRY" env-default:"5m"`
	RefreshTokenExpiry string `env:"REFRESH_TOKEN_EXPIRY" env-default:"15m"`
	TempTokenExpiry    string `env:"TEMP_TOKEN_EXPIRY" env-default:"10m"`
	LogoutTokenExpiry  string `env:"LOGOUT_TOKEN_EXPIRY" env-default:"-1m"`
	Issuer             string `env:"JWT_ISSUER" env-default:"simple-idm"`
	Audience           string `env:"JWT_AUDIENCE" env-default:"simple-idm"`
}

// ParseAccessTokenExpiry parses the access token expiry duration
func (j JWTConfig) ParseAccessTokenExpiry() (time.Duration, error) {
	return parseDurationISO8601(j.AccessTokenExpiry)
}

// ParseRefreshTokenExpiry parses the refresh token expiry duration
func (j JWTConfig) ParseRefreshTokenExpiry() (time.Duration, error) {
	return parseDurationISO8601(j.RefreshTokenExpiry)
}

// ParseTempTokenExpiry parses the temp token expiry duration
func (j JWTConfig) ParseTempTokenExpiry() (time.Duration, error) {
	return parseDurationISO8601(j.TempTokenExpiry)
}

// ParseLogoutTokenExpiry parses the logout token expiry duration
func (j JWTConfig) ParseLogoutTokenExpiry() (time.Duration, error) {
	return parseDurationISO8601(j.LogoutTokenExpiry)
}

// CookieSameSite returns the appropriate SameSite setting based on CookieSecure
func (j JWTConfig) CookieSameSite() http.SameSite {
	if j.CookieSecure {
		return http.SameSiteStrictMode
	}
	return http.SameSiteLaxMode
}

// NewJWTConfigFromEnv creates a JWTConfig from environment variables
func NewJWTConfigFromEnv() JWTConfig {
	return JWTConfig{
		Secret:             GetEnvOrDefault("JWT_SECRET", "very-secure-jwt-secret"),
		CookieHttpOnly:     GetEnvBool("COOKIE_HTTP_ONLY", true),
		CookieSecure:       GetEnvBool("COOKIE_SECURE", true),
		AccessTokenExpiry:  GetEnvOrDefault("ACCESS_TOKEN_EXPIRY", "5m"),
		RefreshTokenExpiry: GetEnvOrDefault("REFRESH_TOKEN_EXPIRY", "15m"),
		TempTokenExpiry:    GetEnvOrDefault("TEMP_TOKEN_EXPIRY", "10m"),
		LogoutTokenExpiry:  GetEnvOrDefault("LOGOUT_TOKEN_EXPIRY", "-1m"),
		Issuer:             GetEnvOrDefault("JWT_ISSUER", "simple-idm"),
		Audience:           GetEnvOrDefault("JWT_AUDIENCE", "simple-idm"),
	}
}

// parseDurationISO8601 tries to parse duration as ISO8601 first, then Go duration
func parseDurationISO8601(s string) (time.Duration, error) {
	// Try ISO8601 format first
	isoDuration, err := duration.Parse(s)
	if err == nil {
		return isoDuration.ToTimeDuration(), nil
	}

	// Fall back to Go duration format
	return time.ParseDuration(s)
}
