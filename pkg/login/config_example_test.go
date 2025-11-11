package login_test

import (
	"time"

	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notification"
)

// Example 1: Using DefaultConfig
func ExampleDefaultConfig() {
	// Get default configuration
	config := login.DefaultConfig()

	// Create service with defaults
	repository := login.NewInMemoryLoginRepository() // or your PostgreSQL repository
	service, _ := login.NewLoginServiceWithConfig(
		repository,
		config,
		// Optional dependencies
		login.WithNotificationManager(nil), // Add your notification manager
		login.WithUserMapper(nil),          // Add your user mapper
	)

	_ = service
}

// Example 2: Customizing configuration
func ExampleCustomConfig() {
	// Start with defaults and customize
	config := login.DefaultConfig()
	config.MaxFailedAttempts = 3                 // Stricter: only 3 attempts
	config.LockoutDuration = 1 * time.Hour       // Longer lockout
	config.MagicLinkTokenExpiration = 10 * time.Minute // Shorter magic link validity

	// Customize password policy
	config.PasswordPolicy.MinLength = 12 // Require 12+ character passwords
	config.PasswordPolicy.RequireSpecial = true
	config.PasswordPolicy.PreventReuse = 5 // Remember last 5 passwords
	config.PasswordPolicy.ExpirationDays = 90 // Passwords expire after 90 days

	repository := login.NewInMemoryLoginRepository()
	service, _ := login.NewLoginServiceWithConfig(repository, config)

	_ = service
}

// Example 3: Production configuration with all options
func ExampleProductionConfig() {
	// Production-grade configuration
	config := login.Config{
		MaxFailedAttempts:        5,
		LockoutDuration:          30 * time.Minute,
		MagicLinkTokenExpiration: 15 * time.Minute,
		PasswordPolicy: &login.PasswordPolicy{
			MinLength:        12,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumber:    true,
			RequireSpecial:   true,
			MaxLength:        128,
			PreventReuse:     10,              // Remember last 10 passwords
			ExpirationDays:   90,              // Passwords expire every 90 days
			CheckDictionary:  true,            // Check against common passwords
			MinEntropyBits:   50,              // Require minimum entropy
		},
	}

	// Validate before use
	if err := config.Validate(); err != nil {
		panic(err)
	}

	// Create service with production dependencies
	repository := login.NewInMemoryLoginRepository() // Use PostgreSQL in production
	notificationManager := &notification.NotificationManager{} // Your notification setup
	userMapper := mapper.UserMapper(nil) // Your user mapper

	service, err := login.NewLoginServiceWithConfig(
		repository,
		config,
		login.WithNotificationManager(notificationManager),
		login.WithUserMapper(userMapper),
	)
	if err != nil {
		panic(err)
	}

	_ = service
}

// Example 4: Loading from environment variables (pattern)
func ExampleConfigFromEnvironment() {
	// This is a pattern you can implement in your application
	// Parse environment variables and create config
	config := login.Config{
		MaxFailedAttempts:        getEnvInt("LOGIN_MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:          getEnvDuration("LOGIN_LOCKOUT_DURATION", 30*time.Minute),
		MagicLinkTokenExpiration: getEnvDuration("LOGIN_MAGIC_LINK_EXPIRATION", 15*time.Minute),
		PasswordPolicy: &login.PasswordPolicy{
			MinLength:        getEnvInt("PASSWORD_MIN_LENGTH", 8),
			RequireUppercase: getEnvBool("PASSWORD_REQUIRE_UPPERCASE", true),
			RequireLowercase: getEnvBool("PASSWORD_REQUIRE_LOWERCASE", true),
			RequireNumber:    getEnvBool("PASSWORD_REQUIRE_NUMBER", true),
			RequireSpecial:   getEnvBool("PASSWORD_REQUIRE_SPECIAL", false),
		},
	}

	if err := config.Validate(); err != nil {
		panic(err)
	}

	_ = config
}

// Example 5: Minimal configuration (lenient for development)
func ExampleDevelopmentConfig() {
	config := login.Config{
		MaxFailedAttempts:        100, // Very lenient for dev
		LockoutDuration:          1 * time.Minute,
		MagicLinkTokenExpiration: 1 * time.Hour, // Long-lived for testing
		PasswordPolicy: &login.PasswordPolicy{
			MinLength:        4,     // Short for dev convenience
			RequireUppercase: false,
			RequireLowercase: false,
			RequireNumber:    false,
			RequireSpecial:   false,
		},
	}

	repository := login.NewInMemoryLoginRepository()
	service, _ := login.NewLoginServiceWithConfig(repository, config)

	_ = service
}

// Helper functions (implement these in your application)
func getEnvInt(key string, defaultVal int) int {
	// Implementation: parse from os.Getenv(key) or return default
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	// Implementation: parse from os.Getenv(key) or return default
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	// Implementation: parse from os.Getenv(key) or return default
	return defaultVal
}
