// Package config provides common configuration utilities and patterns for simple-idm.
//
// This package centralizes configuration loading, validation, and management patterns
// that are used across all services. It eliminates code duplication and provides
// a consistent approach to handling environment variables, validation, and configuration.
//
// # Overview
//
// The config package provides:
//   - Environment variable helpers with type conversion
//   - Configuration validation utilities
//   - Password complexity configuration
//   - Role management utilities
//   - Common configuration patterns
//
// # Environment Variable Helpers
//
// Load configuration from environment variables with automatic type conversion and defaults:
//
//	// String values
//	host := config.GetEnvOrDefault("DB_HOST", "localhost")
//	apiKey := config.MustGetEnv("API_KEY") // Panics if not set
//
//	// Integer values
//	port := config.GetEnvInt("DB_PORT", 5432)
//	maxConns := config.MustGetEnvInt("MAX_CONNECTIONS")
//
//	// Boolean values
//	debug := config.GetEnvBool("DEBUG", false)
//	enabled := config.GetEnvBool("FEATURE_ENABLED", true)
//
//	// Duration values
//	timeout := config.GetEnvDuration("TIMEOUT", 30*time.Second)
//	ttl := config.MustGetEnvDuration("CACHE_TTL")
//
//	// Slice values (comma-separated)
//	urls := config.GetEnvSlice("API_URLS", []string{"http://localhost"})
//
// # Configuration Validation
//
// Validate configuration with structured error handling:
//
//	type DatabaseConfig struct {
//		Host     string
//		Port     uint16
//		Username string
//		Password string
//		Database string
//	}
//
//	func (c *DatabaseConfig) Validate() error {
//		return config.Validate(
//			func() config.ValidationErrors {
//				return config.CollectErrors(
//					config.RequireNonEmpty("host", c.Host),
//					config.RequireValidPort("port", c.Port),
//					config.RequireNonEmpty("username", c.Username),
//					config.RequireNonEmpty("password", c.Password),
//					config.RequireNonEmpty("database", c.Database),
//				)
//			},
//		)
//	}
//
// # Password Policy Configuration
//
// Manage password complexity requirements:
//
//	// Production environment
//	pwdConfig := config.ProductionDefaults()
//	policy := pwdConfig.ToPasswordPolicy()
//
//	// Development environment (relaxed)
//	pwdConfig := config.DevelopmentDefaults()
//
//	// Enterprise compliance (strict)
//	pwdConfig := config.EnterpriseDefaults()
//
//	// Custom configuration
//	pwdConfig := &config.PasswordComplexityConfig{
//		Enabled:            true,
//		RequiredLength:     10,
//		RequiredUppercase:  true,
//		RequiredLowercase:  true,
//		RequiredDigit:      true,
//		HistoryCheckCount:  3,
//		ExpirationPeriod:   "P90D", // 90 days
//	}
//	policy := pwdConfig.ToPasswordPolicy()
//
// # Role Management
//
// Utilities for admin role management:
//
//	// Parse admin roles from environment
//	adminRoles := config.ParseAdminRoleNames("admin,superadmin,root")
//
//	// Check if a role is an admin role
//	isAdmin := config.IsAdminRole("admin", adminRoles)
//
//	// Get primary admin role
//	primary := config.GetPrimaryAdminRole(adminRoles) // "admin"
//
//	// Check if user has any admin role
//	hasAdmin := config.HasAnyAdminRole(userRoles, adminRoles)
//
// # Environment Detection
//
// Detect and respond to different deployment environments:
//
//	env := config.GetEnvironment()
//
//	if config.IsProduction() {
//		// Use production settings
//		enableMetrics()
//		disableDebugLogs()
//	}
//
//	if config.IsDevelopment() {
//		// Use development settings
//		enableHotReload()
//		enableVerboseLogging()
//	}
//
//	// Environment-specific configuration
//	switch env {
//	case config.Production:
//		timeout = 30 * time.Second
//	case config.Staging:
//		timeout = 60 * time.Second
//	case config.Development:
//		timeout = 5 * time.Minute
//	}
//
// # Complete Example
//
// Putting it all together in a service configuration:
//
//	type ServiceConfig struct {
//		// Server settings
//		Host string
//		Port uint16
//
//		// Database settings
//		DatabaseURL string
//		MaxConnections int
//
//		// Auth settings
//		JWTSecret string
//		TokenTTL  time.Duration
//
//		// Feature flags
//		EnableMetrics bool
//		EnableDebug   bool
//
//		// Password policy
//		PasswordPolicy *login.PasswordPolicy
//	}
//
//	func LoadServiceConfig() (*ServiceConfig, error) {
//		cfg := &ServiceConfig{
//			Host:           config.GetEnvOrDefault("HOST", "localhost"),
//			Port:           config.GetEnvUint16("PORT", 8080),
//			DatabaseURL:    config.MustGetEnv("DATABASE_URL"),
//			MaxConnections: config.GetEnvInt("MAX_CONNECTIONS", 10),
//			JWTSecret:      config.MustGetEnv("JWT_SECRET"),
//			TokenTTL:       config.GetEnvDuration("TOKEN_TTL", 1*time.Hour),
//			EnableMetrics:  config.GetEnvBool("ENABLE_METRICS", true),
//			EnableDebug:    config.GetEnvBool("DEBUG", config.IsDevelopment()),
//		}
//
//		// Load password policy based on environment
//		var pwdConfig *config.PasswordComplexityConfig
//		if config.IsProduction() {
//			pwdConfig = config.ProductionDefaults()
//		} else {
//			pwdConfig = config.DevelopmentDefaults()
//		}
//		cfg.PasswordPolicy = pwdConfig.ToPasswordPolicy()
//
//		// Validate configuration
//		if err := cfg.Validate(); err != nil {
//			return nil, fmt.Errorf("invalid configuration: %w", err)
//		}
//
//		return cfg, nil
//	}
//
//	func (c *ServiceConfig) Validate() error {
//		return config.Validate(
//			func() config.ValidationErrors {
//				return config.CollectErrors(
//					config.RequireNonEmpty("host", c.Host),
//					config.RequireValidPort("port", c.Port),
//					config.RequireNonEmpty("database_url", c.DatabaseURL),
//					config.RequirePositive("max_connections", c.MaxConnections),
//					config.RequireMinLength("jwt_secret", c.JWTSecret, 32),
//					config.RequirePositiveDuration("token_ttl", c.TokenTTL),
//				)
//			},
//		)
//	}
//
// # Best Practices
//
// 1. Use MustGetEnv for required configuration during initialization
//   - Fail fast if critical configuration is missing
//   - Use GetEnvOrDefault for optional configuration with sensible defaults
//
// 2. Always validate configuration before using it
//   - Use the Validate() function with structured validators
//   - Return descriptive errors that help with debugging
//
// 3. Use environment-specific defaults
//   - Production: Secure and conservative defaults
//   - Development: Relaxed settings for faster development
//   - Staging: Production-like settings for testing
//
// 4. Document configuration requirements
//   - List all environment variables your service uses
//   - Specify which are required vs optional
//   - Document default values and formats
//
// 5. Centralize configuration loading
//   - Create a single LoadConfig() function per service
//   - Load all configuration in one place
//   - Validate before returning the config object
//
// # Security Considerations
//
// - Never log sensitive configuration values (passwords, secrets, keys)
// - Use HTTPS URLs in production (RequireHTTPSURL validator)
// - Enforce strong password policies in production
// - Validate all external configuration inputs
// - Use environment variables for secrets, not config files
//
// # Common Patterns
//
// Pattern 1: Configuration with defaults
//
//	type Config struct {
//		Timeout time.Duration
//	}
//
//	func DefaultConfig() *Config {
//		return &Config{
//			Timeout: 30 * time.Second,
//		}
//	}
//
//	func LoadFromEnv() *Config {
//		cfg := DefaultConfig()
//		cfg.Timeout = config.GetEnvDuration("TIMEOUT", cfg.Timeout)
//		return cfg
//	}
//
// Pattern 2: Validation with early returns
//
//	func (c *Config) Validate() error {
//		if err := config.RequirePositiveDuration("timeout", c.Timeout); err != nil {
//			return err
//		}
//		if c.Timeout > 5*time.Minute {
//			return fmt.Errorf("timeout too long: %v", c.Timeout)
//		}
//		return nil
//	}
//
// Pattern 3: Optional field validation
//
//	func (c *Config) Validate() error {
//		return config.Validate(
//			func() config.ValidationErrors {
//				errs := config.CollectErrors(
//					config.RequireNonEmpty("name", c.Name),
//				)
//
//				// Only validate webhook URL if it's set
//				if webhookErr := config.WhenSet(c.WebhookURL,
//					func() *config.ValidationError {
//						return config.RequireHTTPSURL("webhook_url", c.WebhookURL)
//					}); webhookErr != nil {
//					errs = append(errs, *webhookErr)
//				}
//
//				return errs
//			},
//		)
//	}
package config
