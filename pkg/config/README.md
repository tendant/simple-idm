# Config Package

Common configuration utilities and patterns for simple-idm.

## Overview

The `config` package provides centralized configuration management utilities that eliminate code duplication across services. It offers type-safe environment variable loading, structured validation, and common configuration patterns.

## Features

- **Environment Variable Helpers** - Type-safe loading with defaults
- **Configuration Validation** - Structured error handling
- **Password Policy Management** - Pre-configured security policies
- **Role Management** - Admin role utilities
- **Environment Detection** - Deployment environment helpers

## Quick Start

```go
package main

import (
    "fmt"
    "time"

    "github.com/tendant/simple-idm/pkg/config"
)

type AppConfig struct {
    Port           uint16
    DatabaseURL    string
    CacheTimeout   time.Duration
    EnableMetrics  bool
}

func LoadConfig() (*AppConfig, error) {
    cfg := &AppConfig{
        Port:          config.GetEnvUint16("PORT", 8080),
        DatabaseURL:   config.MustGetEnv("DATABASE_URL"),
        CacheTimeout:  config.GetEnvDuration("CACHE_TIMEOUT", 5*time.Minute),
        EnableMetrics: config.GetEnvBool("ENABLE_METRICS", true),
    }

    if err := cfg.Validate(); err != nil {
        return nil, err
    }

    return cfg, nil
}

func (c *AppConfig) Validate() error {
    return config.Validate(
        func() config.ValidationErrors {
            return config.CollectErrors(
                config.RequireValidPort("port", c.Port),
                config.RequireNonEmpty("database_url", c.DatabaseURL),
                config.RequirePositiveDuration("cache_timeout", c.CacheTimeout),
            )
        },
    )
}
```

## API Reference

### Environment Variable Helpers

| Function | Description | Example |
|----------|-------------|---------|
| `GetEnv(key)` | Get environment variable | `config.GetEnv("DEBUG")` |
| `GetEnvOrDefault(key, default)` | Get with fallback | `config.GetEnvOrDefault("HOST", "localhost")` |
| `MustGetEnv(key)` | Get or panic | `config.MustGetEnv("API_KEY")` |
| `GetEnvInt(key, default)` | Get as integer | `config.GetEnvInt("PORT", 8080)` |
| `GetEnvUint16(key, default)` | Get as uint16 (ports) | `config.GetEnvUint16("PORT", 8080)` |
| `GetEnvBool(key, default)` | Get as boolean | `config.GetEnvBool("DEBUG", false)` |
| `GetEnvDuration(key, default)` | Get as duration | `config.GetEnvDuration("TIMEOUT", 30*time.Second)` |
| `GetEnvSlice(key, default)` | Get as string slice | `config.GetEnvSlice("URLS", []string{})` |

### Validation Helpers

| Function | Description |
|----------|-------------|
| `RequireNonEmpty(field, value)` | Validate non-empty string |
| `RequirePositive(field, value)` | Validate positive integer |
| `RequireNonNegative(field, value)` | Validate non-negative integer |
| `RequirePositiveDuration(field, value)` | Validate positive duration |
| `RequireInRange(field, value, min, max)` | Validate integer range |
| `RequireValidURL(field, value)` | Validate URL format |
| `RequireHTTPSURL(field, value)` | Validate HTTPS URL |
| `RequireValidEmail(field, value)` | Validate email format |
| `RequireValidPort(field, value)` | Validate port number |
| `RequireOneOf(field, value, allowed)` | Validate enum value |
| `RequireMinLength(field, value, min)` | Validate min string length |
| `RequireMaxLength(field, value, max)` | Validate max string length |

### Password Policy

```go
// Production defaults
pwdConfig := config.ProductionDefaults()
policy := pwdConfig.ToPasswordPolicy()

// Development defaults (relaxed)
pwdConfig := config.DevelopmentDefaults()

// Enterprise defaults (strict)
pwdConfig := config.EnterpriseDefaults()

// Custom configuration
pwdConfig := &config.PasswordComplexityConfig{
    Enabled:            true,
    RequiredLength:     12,
    RequiredUppercase:  true,
    RequiredLowercase:  true,
    RequiredDigit:      true,
    DisallowCommonPwds: true,
    HistoryCheckCount:  5,
    ExpirationPeriod:   "P90D", // 90 days
}
```

### Role Management

```go
// Parse admin roles from comma-separated string
adminRoles := config.ParseAdminRoleNames("admin,superadmin,root")

// Check if role is admin
isAdmin := config.IsAdminRole("admin", adminRoles)

// Get primary admin role
primary := config.GetPrimaryAdminRole(adminRoles)

// Check if user has any admin role
hasAdmin := config.HasAnyAdminRole(userRoles, adminRoles)
```

### Environment Detection

```go
env := config.GetEnvironment()

if config.IsProduction() {
    // Production settings
}

if config.IsDevelopment() {
    // Development settings
}

switch env {
case config.Production:
    // Production
case config.Staging:
    // Staging
case config.Development:
    // Development
case config.Test:
    // Test
}
```

## Examples

### Example 1: Database Configuration

```go
type DatabaseConfig struct {
    Host         string
    Port         uint16
    Username     string
    Password     string
    Database     string
    MaxConns     int
    Timeout      time.Duration
}

func LoadDatabaseConfig() (*DatabaseConfig, error) {
    cfg := &DatabaseConfig{
        Host:     config.GetEnvOrDefault("DB_HOST", "localhost"),
        Port:     config.GetEnvUint16("DB_PORT", 5432),
        Username: config.MustGetEnv("DB_USERNAME"),
        Password: config.MustGetEnv("DB_PASSWORD"),
        Database: config.GetEnvOrDefault("DB_NAME", "app_db"),
        MaxConns: config.GetEnvInt("DB_MAX_CONNS", 10),
        Timeout:  config.GetEnvDuration("DB_TIMEOUT", 30*time.Second),
    }

    if err := cfg.Validate(); err != nil {
        return nil, err
    }

    return cfg, nil
}

func (c *DatabaseConfig) Validate() error {
    return config.Validate(
        func() config.ValidationErrors {
            return config.CollectErrors(
                config.RequireNonEmpty("host", c.Host),
                config.RequireValidPort("port", c.Port),
                config.RequireNonEmpty("username", c.Username),
                config.RequireNonEmpty("password", c.Password),
                config.RequireNonEmpty("database", c.Database),
                config.RequireInRange("max_conns", c.MaxConns, 1, 100),
                config.RequirePositiveDuration("timeout", c.Timeout),
            )
        },
    )
}
```

### Example 2: Service Configuration with Features

```go
type ServiceConfig struct {
    ServerHost    string
    ServerPort    uint16
    APIBaseURL    string
    AdminEmails   []string
    EnableMetrics bool
    EnableDebug   bool
    RateLimitRPS  int
}

func LoadServiceConfig() (*ServiceConfig, error) {
    cfg := &ServiceConfig{
        ServerHost:    config.GetEnvOrDefault("HOST", "0.0.0.0"),
        ServerPort:    config.GetEnvUint16("PORT", 8080),
        APIBaseURL:    config.MustGetEnv("API_BASE_URL"),
        AdminEmails:   config.GetEnvSlice("ADMIN_EMAILS", []string{}),
        EnableMetrics: config.GetEnvBool("ENABLE_METRICS", config.IsProduction()),
        EnableDebug:   config.GetEnvBool("DEBUG", config.IsDevelopment()),
        RateLimitRPS:  config.GetEnvInt("RATE_LIMIT_RPS", 100),
    }

    if err := cfg.Validate(); err != nil {
        return nil, err
    }

    return cfg, nil
}

func (c *ServiceConfig) Validate() error {
    return config.Validate(
        func() config.ValidationErrors {
            errs := config.CollectErrors(
                config.RequireNonEmpty("server_host", c.ServerHost),
                config.RequireValidPort("server_port", c.ServerPort),
                config.RequireHTTPSURL("api_base_url", c.APIBaseURL),
                config.RequirePositive("rate_limit_rps", c.RateLimitRPS),
            )

            // Validate admin emails
            for i, email := range c.AdminEmails {
                if err := config.RequireValidEmail(
                    fmt.Sprintf("admin_emails[%d]", i),
                    email,
                ); err != nil {
                    errs = append(errs, *err)
                }
            }

            return errs
        },
    )
}
```

### Example 3: Optional Configuration

```go
type CacheConfig struct {
    Enabled    bool
    RedisURL   string
    TTL        time.Duration
    MaxEntries int
}

func (c *CacheConfig) Validate() error {
    return config.Validate(
        func() config.ValidationErrors {
            // Base validation
            errs := config.CollectErrors(
                config.RequirePositiveDuration("ttl", c.TTL),
                config.RequirePositive("max_entries", c.MaxEntries),
            )

            // Only validate Redis URL if cache is enabled
            if c.Enabled {
                if err := config.RequireValidURL("redis_url", c.RedisURL); err != nil {
                    errs = append(errs, *err)
                }
            }

            return errs
        },
    )
}
```

## Shared Configuration Types

The package provides pre-built configuration structs for common IDM functionality:

### LoginConfig

Login behavior settings:

```go
// Load from environment variables
cfg := config.NewLoginConfigFromEnv()

// Or construct directly
cfg := config.LoginConfig{
    MaxLoginAttempts:         5,
    LockoutDuration:          15 * time.Minute,
    EnableRegistration:       true,
    MagicLinkExpiration:      15 * time.Minute,
    TemporaryPasswordExpiry:  24 * time.Hour,
}
```

| Environment Variable | Field | Default |
|---------------------|-------|---------|
| `LOGIN_MAX_ATTEMPTS` | MaxLoginAttempts | 5 |
| `LOGIN_LOCKOUT_DURATION` | LockoutDuration | 15m |
| `LOGIN_ENABLE_REGISTRATION` | EnableRegistration | true |
| `MAGIC_LINK_EXPIRATION` | MagicLinkExpiration | 15m |
| `TEMPORARY_PASSWORD_EXPIRY` | TemporaryPasswordExpiry | 24h |

### ExternalProviderConfig

OAuth2 external provider settings:

```go
// Load from environment variables
cfg := config.NewExternalProviderConfigFromEnv()

// Check if any providers are enabled
if cfg.HasEnabledProviders() {
    // Configure external auth
}
```

| Environment Variable | Field | Default |
|---------------------|-------|---------|
| `GOOGLE_CLIENT_ID` | GoogleClientID | "" |
| `GOOGLE_CLIENT_SECRET` | GoogleClientSecret | "" |
| `GOOGLE_ENABLED` | GoogleEnabled | false |
| `MICROSOFT_CLIENT_ID` | MicrosoftClientID | "" |
| `MICROSOFT_CLIENT_SECRET` | MicrosoftClientSecret | "" |
| `MICROSOFT_ENABLED` | MicrosoftEnabled | false |
| `GITHUB_CLIENT_ID` | GitHubClientID | "" |
| `GITHUB_CLIENT_SECRET` | GitHubClientSecret | "" |
| `GITHUB_ENABLED` | GitHubEnabled | false |
| `LINKEDIN_CLIENT_ID` | LinkedInClientID | "" |
| `LINKEDIN_CLIENT_SECRET` | LinkedInClientSecret | "" |
| `LINKEDIN_ENABLED` | LinkedInEnabled | false |

### JWKSConfig

RSA key settings for JWT signing:

```go
// Load from environment variables
cfg := config.NewJWKSConfigFromEnv()

// Or with defaults
cfg := config.DefaultJWKSConfig()
```

| Environment Variable | Field | Default |
|---------------------|-------|---------|
| `JWKS_PRIVATE_KEY_FILE` | PrivateKeyFile | "jwt-private.pem" |
| `JWKS_KEY_ID` | KeyID | "key-1" |
| `JWKS_ALGORITHM` | Algorithm | "RS256" |

### RateLimitConfig

Rate limiting settings:

```go
// Load from environment variables
cfg := config.NewRateLimitConfigFromEnv()

// Or with defaults (100 req/s, burst 200)
cfg := config.DefaultRateLimitConfig()
```

| Environment Variable | Field | Default |
|---------------------|-------|---------|
| `RATE_LIMIT_REQUESTS_PER_SECOND` | RequestsPerSecond | 100 |
| `RATE_LIMIT_BURST` | Burst | 200 |
| `RATE_LIMIT_ENABLED` | Enabled | true |

### SessionManagementConfig

Session tracking settings:

```go
// Load from environment variables
cfg := config.NewSessionManagementConfigFromEnv()
```

| Environment Variable | Field | Default |
|---------------------|-------|---------|
| `SESSION_TRACKING_ENABLED` | TrackingEnabled | true |
| `SESSION_MAX_CONCURRENT` | MaxConcurrentSessions | 5 |
| `SESSION_IDLE_TIMEOUT` | IdleTimeout | 30m |

### OAuth2ClientConfig

OAuth2 client encryption settings:

```go
// Load from environment variables
cfg := config.NewOAuth2ClientConfigFromEnv()
```

| Environment Variable | Field | Default |
|---------------------|-------|---------|
| `OAUTH2_CLIENT_ENCRYPTION_KEY` | EncryptionKey | "" |

## Best Practices

1. **Use MustGetEnv for critical configuration**
   - Fail fast during startup if required config is missing
   - Better than runtime errors later

2. **Always validate configuration**
   - Validate immediately after loading
   - Return descriptive errors for debugging

3. **Use environment-specific defaults**
   ```go
   debug := config.GetEnvBool("DEBUG", config.IsDevelopment())
   ```

4. **Document environment variables**
   - Create .env.example files
   - Document required vs optional variables
   - Include example values

5. **Never log secrets**
   - Mask passwords and API keys in logs
   - Use structured logging to filter sensitive fields

## Migration from Old Patterns

### Before (manual parsing)

```go
portStr := os.Getenv("PORT")
port, err := strconv.Atoi(portStr)
if err != nil {
    port = 8080
}
```

### After (using config package)

```go
port := config.GetEnvInt("PORT", 8080)
```

---

For complete documentation and examples, see [doc.go](doc.go).
