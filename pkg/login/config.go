package login

import (
	"fmt"
	"time"
)

// Config holds configuration for the LoginService
// Use this struct for environment-based configuration or programmatic setup
type Config struct {
	// Account Lockout Settings
	MaxFailedAttempts int           `json:"max_failed_attempts"` // Maximum failed login attempts before lockout (default: 5)
	LockoutDuration   time.Duration `json:"lockout_duration"`    // Duration to lock account after max failures (default: 30m)

	// Magic Link Settings
	MagicLinkTokenExpiration time.Duration `json:"magic_link_token_expiration"` // Magic link token validity (default: 15m)

	// Note: Password policy configuration is handled by PasswordPolicyChecker
	// See policychecker.go for PasswordPolicy struct and DefaultPasswordPolicy
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxFailedAttempts:        5,
		LockoutDuration:          30 * time.Minute,
		MagicLinkTokenExpiration: 15 * time.Minute,
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.MaxFailedAttempts < 0 {
		return fmt.Errorf("max_failed_attempts must be non-negative, got %d", c.MaxFailedAttempts)
	}

	if c.LockoutDuration < 0 {
		return fmt.Errorf("lockout_duration must be non-negative, got %v", c.LockoutDuration)
	}

	if c.MagicLinkTokenExpiration <= 0 {
		return fmt.Errorf("magic_link_token_expiration must be positive, got %v", c.MagicLinkTokenExpiration)
	}

	return nil
}

// WithConfig is a functional option that applies a Config to the LoginService
func WithConfig(config Config) Option {
	return func(ls *LoginService) {
		ls.maxFailedAttempts = config.MaxFailedAttempts
		ls.lockoutDuration = config.LockoutDuration
		ls.magicLinkTokenExpiration = config.MagicLinkTokenExpiration
	}
}

// NewLoginServiceWithConfig creates a LoginService with the provided config
// This is a convenience constructor that combines config and functional options
//
// Example:
//
//	config := login.DefaultConfig()
//	config.MaxFailedAttempts = 3
//	config.LockoutDuration = 1 * time.Hour
//
//	service := login.NewLoginServiceWithConfig(
//	    repository,
//	    config,
//	    login.WithNotificationManager(notificationManager),
//	    login.WithUserMapper(userMapper),
//	)
func NewLoginServiceWithConfig(repository LoginRepository, config Config, opts ...Option) (*LoginService, error) {
	// Validate config first
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create service with config using WithConfig option
	allOpts := append([]Option{WithConfig(config)}, opts...)
	return NewLoginServiceWithOptions(repository, allOpts...), nil
}
