package config

import (
	"time"

	"github.com/sosodev/duration"
)

// LoginConfig contains login behavior settings.
// Fields have no env tags - populate manually or use NewLoginConfigFromEnv() for standard env var names.
type LoginConfig struct {
	// MaxFailedAttempts is the maximum number of failed login attempts before lockout
	MaxFailedAttempts int

	// LockoutDuration is the duration to lock out after max failed attempts (ISO 8601 format, e.g., "PT15M")
	LockoutDuration string

	// DeviceExpirationDays is how long device recognition lasts (ISO 8601 format, e.g., "P90D")
	DeviceExpirationDays string

	// RegistrationEnabled controls whether new user registration is allowed
	RegistrationEnabled bool

	// RegistrationDefaultRole is the default role assigned to newly registered users
	RegistrationDefaultRole string

	// MagicLinkTokenExpiration is the validity period for magic link tokens (ISO 8601 format, e.g., "PT6H")
	MagicLinkTokenExpiration string

	// PhoneVerificationSecret is the secret used for phone verification HMAC
	PhoneVerificationSecret string
}

// DefaultLoginConfig returns a LoginConfig with sensible defaults
func DefaultLoginConfig() LoginConfig {
	return LoginConfig{
		MaxFailedAttempts:        10000, // Effectively disabled
		LockoutDuration:          "PT0M",
		DeviceExpirationDays:     "P90D",
		RegistrationEnabled:      false,
		RegistrationDefaultRole:  "readonlyuser",
		MagicLinkTokenExpiration: "PT6H",
		PhoneVerificationSecret:  "secret",
	}
}

// NewLoginConfigFromEnv loads LoginConfig from standard environment variables.
// This is an optional convenience function - you can also populate the struct manually.
//
// Environment variables:
//   - LOGIN_MAX_FAILED_ATTEMPTS: Maximum failed login attempts (default: 10000)
//   - LOGIN_LOCKOUT_DURATION: Lockout duration in ISO 8601 format (default: "PT0M")
//   - DEVICE_EXPIRATION_DAYS: Device recognition expiry in ISO 8601 format (default: "P90D")
//   - LOGIN_REGISTRATION_ENABLED: Enable user registration (default: false)
//   - LOGIN_REGISTRATION_DEFAULT_ROLE: Default role for new users (default: "readonlyuser")
//   - MAGIC_LINK_TOKEN_EXPIRATION: Magic link token validity in ISO 8601 format (default: "PT6H")
//   - PHONE_VERIFICATION_SECRET: Secret for phone verification HMAC (default: "secret")
func NewLoginConfigFromEnv() LoginConfig {
	return LoginConfig{
		MaxFailedAttempts:        GetEnvInt("LOGIN_MAX_FAILED_ATTEMPTS", 10000),
		LockoutDuration:          GetEnvOrDefault("LOGIN_LOCKOUT_DURATION", "PT0M"),
		DeviceExpirationDays:     GetEnvOrDefault("DEVICE_EXPIRATION_DAYS", "P90D"),
		RegistrationEnabled:      GetEnvBool("LOGIN_REGISTRATION_ENABLED", false),
		RegistrationDefaultRole:  GetEnvOrDefault("LOGIN_REGISTRATION_DEFAULT_ROLE", "readonlyuser"),
		MagicLinkTokenExpiration: GetEnvOrDefault("MAGIC_LINK_TOKEN_EXPIRATION", "PT6H"),
		PhoneVerificationSecret:  GetEnvOrDefault("PHONE_VERIFICATION_SECRET", "secret"),
	}
}

// ParseLockoutDuration parses the LockoutDuration field as a time.Duration.
// Supports ISO 8601 duration format (e.g., "PT15M") and Go duration format (e.g., "15m").
func (c *LoginConfig) ParseLockoutDuration() (time.Duration, error) {
	return parseISO8601OrGoDuration(c.LockoutDuration)
}

// ParseDeviceExpiration parses the DeviceExpirationDays field as a time.Duration.
// Supports ISO 8601 duration format (e.g., "P90D") and Go duration format (e.g., "2160h").
func (c *LoginConfig) ParseDeviceExpiration() (time.Duration, error) {
	return parseISO8601OrGoDuration(c.DeviceExpirationDays)
}

// ParseMagicLinkExpiration parses the MagicLinkTokenExpiration field as a time.Duration.
// Supports ISO 8601 duration format (e.g., "PT6H") and Go duration format (e.g., "6h").
func (c *LoginConfig) ParseMagicLinkExpiration() (time.Duration, error) {
	return parseISO8601OrGoDuration(c.MagicLinkTokenExpiration)
}

// parseISO8601OrGoDuration tries to parse as ISO 8601 first, then as Go duration
func parseISO8601OrGoDuration(s string) (time.Duration, error) {
	// Try ISO 8601 format first
	isoDuration, err := duration.Parse(s)
	if err == nil {
		return isoDuration.ToTimeDuration(), nil
	}

	// Fall back to Go duration format
	return time.ParseDuration(s)
}
