package oidc_test

import (
	"time"

	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/oidc"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Example 1: Using DefaultConfig
func ExampleDefaultConfig() {
	// Get default configuration
	config := oidc.DefaultConfig()

	// Create service with defaults
	repository := oidc.NewInMemoryOIDCRepository()
	clientService := &oauth2client.ClientService{} // Your OAuth2 client service

	service, _ := oidc.NewOIDCServiceWithConfig(
		repository,
		clientService,
		config,
		// Optional dependencies
		oidc.WithTokenGenerator(nil), // Add your token generator
		oidc.WithUserMapper(nil),     // Add your user mapper
	)

	_ = service
}

// Example 2: Production configuration
func ExampleProductionConfig() {
	// Production configuration with custom URLs
	config := oidc.Config{
		CodeExpiration:  10 * time.Minute,
		TokenExpiration: 1 * time.Hour,
		BaseURL:         "https://auth.example.com",
		LoginURL:        "https://app.example.com/login",
		Issuer:          "my-production-app",
		AllowedRedirectURIs: []string{
			"https://app.example.com/callback",
			"https://app.example.com/oauth/callback",
		},
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		panic(err)
	}

	// Create service with production dependencies
	repository := oidc.NewInMemoryOIDCRepository() // Use persistent storage in production
	clientService := &oauth2client.ClientService{} // Your client service
	tokenGenerator := tokengenerator.TokenGenerator(nil) // Your RSA token generator
	userMapper := mapper.UserMapper(nil) // Your user mapper

	service, err := oidc.NewOIDCServiceWithConfig(
		repository,
		clientService,
		config,
		oidc.WithTokenGenerator(tokenGenerator),
		oidc.WithUserMapper(userMapper),
	)
	if err != nil {
		panic(err)
	}

	_ = service
}

// Example 3: Development configuration
func ExampleDevelopmentConfig() {
	config := oidc.Config{
		CodeExpiration:  30 * time.Minute, // Longer for dev convenience
		TokenExpiration: 24 * time.Hour,   // Long-lived tokens for testing
		BaseURL:         "http://localhost:4000",
		LoginURL:        "http://localhost:3000/login",
		Issuer:          "dev-app",
		AllowedRedirectURIs: []string{
			"http://localhost:3000/callback",
			"http://localhost:5173/callback", // Vite dev server
		},
	}

	repository := oidc.NewInMemoryOIDCRepository()
	clientService := &oauth2client.ClientService{}

	service, _ := oidc.NewOIDCServiceWithConfig(repository, clientService, config)

	_ = service
}

// Example 4: Multi-environment configuration pattern
func ExampleMultiEnvironmentConfig() {
	// Determine environment
	env := getEnv("ENVIRONMENT", "development")

	var config oidc.Config

	switch env {
	case "production":
		config = oidc.Config{
			CodeExpiration:  10 * time.Minute,
			TokenExpiration: 1 * time.Hour,
			BaseURL:         getEnv("OIDC_BASE_URL", "https://auth.example.com"),
			LoginURL:        getEnv("OIDC_LOGIN_URL", "https://app.example.com/login"),
			Issuer:          getEnv("OIDC_ISSUER", "production-app"),
		}

	case "staging":
		config = oidc.Config{
			CodeExpiration:  15 * time.Minute,
			TokenExpiration: 2 * time.Hour,
			BaseURL:         getEnv("OIDC_BASE_URL", "https://staging-auth.example.com"),
			LoginURL:        getEnv("OIDC_LOGIN_URL", "https://staging-app.example.com/login"),
			Issuer:          getEnv("OIDC_ISSUER", "staging-app"),
		}

	default: // development
		config = oidc.DefaultConfig()
		config.BaseURL = getEnv("OIDC_BASE_URL", "http://localhost:4000")
		config.LoginURL = getEnv("OIDC_LOGIN_URL", "http://localhost:3000/login")
	}

	// Validate
	if err := config.Validate(); err != nil {
		panic(err)
	}

	_ = config
}

// Example 5: Customizing timeouts for mobile apps
func ExampleMobileAppConfig() {
	// Mobile apps often need longer token lifetimes
	config := oidc.Config{
		CodeExpiration:  5 * time.Minute,  // Short code lifetime for security
		TokenExpiration: 24 * time.Hour,   // Longer token for better mobile UX
		BaseURL:         "https://auth.example.com",
		LoginURL:        "https://app.example.com/login",
		Issuer:          "mobile-app",
		AllowedRedirectURIs: []string{
			"myapp://oauth/callback",      // Custom URL scheme
			"https://app.example.com/oauth", // Web fallback
		},
	}

	repository := oidc.NewInMemoryOIDCRepository()
	clientService := &oauth2client.ClientService{}

	service, _ := oidc.NewOIDCServiceWithConfig(repository, clientService, config)

	_ = service
}

// Example 6: Loading from environment variables (recommended pattern)
func ExampleConfigFromEnvironment() {
	config := oidc.Config{
		CodeExpiration:  parseDuration(getEnv("OIDC_CODE_EXPIRATION", "10m")),
		TokenExpiration: parseDuration(getEnv("OIDC_TOKEN_EXPIRATION", "1h")),
		BaseURL:         getEnv("OIDC_BASE_URL", "http://localhost:4000"),
		LoginURL:        getEnv("OIDC_LOGIN_URL", "http://localhost:3000/login"),
		Issuer:          getEnv("OIDC_ISSUER", "simple-idm"),
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		panic(err)
	}

	_ = config
}

// Example 7: Using functional options (backward compatible)
func ExampleBackwardCompatibleUsage() {
	// The old functional options pattern still works!
	repository := oidc.NewInMemoryOIDCRepository()
	clientService := &oauth2client.ClientService{}

	// Use functional options directly (without Config struct)
	service := oidc.NewOIDCServiceWithOptions(
		repository,
		clientService,
		oidc.WithBaseURL("https://auth.example.com"),
		oidc.WithLoginURL("https://app.example.com/login"),
		oidc.WithIssuer("my-app"),
		oidc.WithCodeExpiration(10*time.Minute),
		oidc.WithTokenExpiration(1*time.Hour),
	)

	_ = service
}

// Helper functions (implement these in your application)
func getEnv(key, defaultVal string) string {
	// Implementation: return os.Getenv(key) or default
	return defaultVal
}

func parseDuration(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}
