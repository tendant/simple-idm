package oidc

import (
	"fmt"
	"net/url"
	"time"

	"github.com/tendant/simple-idm/pkg/oauth2client"
)

// Config holds configuration for the OIDCService
// Use this struct for environment-based configuration or programmatic setup
type Config struct {
	// Token Settings
	CodeExpiration  time.Duration `json:"code_expiration"`  // Authorization code expiration (default: 10m)
	TokenExpiration time.Duration `json:"token_expiration"` // Access token expiration (default: 1h)

	// URL Settings
	BaseURL  string `json:"base_url"`  // Base URL of the OIDC server (e.g., "https://auth.example.com")
	LoginURL string `json:"login_url"` // URL for login page (e.g., "https://app.example.com/login")
	Issuer   string `json:"issuer"`    // JWT issuer (default: "simple-idm")

	// Optional: Custom redirect URIs allowed for clients
	AllowedRedirectURIs []string `json:"allowed_redirect_uris,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		CodeExpiration:  10 * time.Minute,
		TokenExpiration: 1 * time.Hour,
		Issuer:          "simple-idm",
		BaseURL:         "http://localhost:4000",
		LoginURL:        "http://localhost:3000/login",
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.CodeExpiration <= 0 {
		return fmt.Errorf("code_expiration must be positive, got %v", c.CodeExpiration)
	}

	if c.TokenExpiration <= 0 {
		return fmt.Errorf("token_expiration must be positive, got %v", c.TokenExpiration)
	}

	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}

	if c.LoginURL == "" {
		return fmt.Errorf("login_url is required")
	}

	if c.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}

	// Validate URLs are properly formatted
	if _, err := url.Parse(c.BaseURL); err != nil {
		return fmt.Errorf("invalid base_url: %w", err)
	}

	if _, err := url.Parse(c.LoginURL); err != nil {
		return fmt.Errorf("invalid login_url: %w", err)
	}

	// Validate redirect URIs if provided
	for i, uri := range c.AllowedRedirectURIs {
		if _, err := url.Parse(uri); err != nil {
			return fmt.Errorf("invalid redirect_uri at index %d: %w", i, err)
		}
	}

	return nil
}

// WithConfig is a functional option that applies a Config to the OIDCService
func WithConfig(config Config) Option {
	return func(s *OIDCService) {
		s.codeExpiration = config.CodeExpiration
		s.tokenExpiration = config.TokenExpiration
		s.baseURL = config.BaseURL
		s.loginURL = config.LoginURL
		s.issuer = config.Issuer
	}
}

// NewOIDCServiceWithConfig creates an OIDCService with the provided config
// This is a convenience constructor that combines config and functional options
//
// Example:
//
//	config := oidc.DefaultConfig()
//	config.BaseURL = "https://auth.example.com"
//	config.LoginURL = "https://app.example.com/login"
//	config.Issuer = "my-app"
//
//	service := oidc.NewOIDCServiceWithConfig(
//	    repository,
//	    clientService,
//	    config,
//	    oidc.WithTokenGenerator(tokenGenerator),
//	    oidc.WithUserMapper(userMapper),
//	)
func NewOIDCServiceWithConfig(
	repository OIDCRepository,
	clientService *oauth2client.ClientService,
	config Config,
	opts ...Option,
) (*OIDCService, error) {
	// Validate config first
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create service with config values
	service := &OIDCService{
		repository:      repository,
		clientService:   clientService,
		codeExpiration:  config.CodeExpiration,
		tokenExpiration: config.TokenExpiration,
		baseURL:         config.BaseURL,
		loginURL:        config.LoginURL,
		issuer:          config.Issuer,
	}

	// Apply additional options (for dependencies)
	for _, opt := range opts {
		opt(service)
	}

	return service, nil
}

// ConfigFromEnv loads OIDC configuration from environment variables
// This is a helper function for common deployment scenarios
//
// Environment variables:
//   - OIDC_BASE_URL: Base URL of the OIDC server (required)
//   - OIDC_LOGIN_URL: Login page URL (required)
//   - OIDC_ISSUER: JWT issuer (default: "simple-idm")
//   - OIDC_CODE_EXPIRATION: Code expiration (default: "10m")
//   - OIDC_TOKEN_EXPIRATION: Token expiration (default: "1h")
//
// Example:
//
//	config, err := oidc.ConfigFromEnv()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	service := oidc.NewOIDCServiceWithConfig(repo, clientService, config)
func ConfigFromEnv() (Config, error) {
	// This is a placeholder - actual implementation would use os.Getenv
	// Left as example for users to implement based on their env var naming
	return DefaultConfig(), nil
}
