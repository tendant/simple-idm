package config

import "fmt"

// PrefixConfig holds configurable API endpoint prefixes for all route groups.
// This allows flexible API gateway routing and versioning support.
//
// Example environment variables:
//
//	API_PREFIX_AUTH=/api/v1/idm/auth
//	API_PREFIX_SIGNUP=/api/v1/idm/signup
//	API_PREFIX_PROFILE=/api/v1/idm/profile
//	API_PREFIX_2FA=/api/v1/idm/2fa
//	API_PREFIX_EMAIL=/api/v1/idm/email
//	API_PREFIX_PASSWORD_RESET=/api/v1/idm/password-reset
//	API_PREFIX_OAUTH2=/api/v1/oauth2
//	API_PREFIX_USERS=/api/v1/idm/users
//	API_PREFIX_ROLES=/api/v1/idm/roles
//	API_PREFIX_DEVICE=/api/v1/idm/device
//	API_PREFIX_LOGINS=/api/v1/idm/logins
//	API_PREFIX_OAUTH2_CLIENTS=/api/v1/idm/oauth2-clients
//	API_PREFIX_EXTERNAL=/api/v1/idm/external
type PrefixConfig struct {
	Auth           string // Authentication endpoints (login, logout, magic link, token refresh)
	Signup         string // User registration endpoints (passwordless, password-based)
	Profile        string // Profile management endpoints (username, phone, password updates)
	TwoFA          string // Two-factor authentication endpoints (setup, enable, disable, validate)
	Email          string // Email verification endpoints (verify, resend, status)
	PasswordReset  string // Password reset endpoints (initiate, reset, policy)
	OAuth2         string // OAuth2 standard endpoints (token, authorize, userinfo)
	Users          string // User management endpoints (admin)
	Roles          string // Role management endpoints (admin)
	Device         string // Device management endpoints
	Logins         string // Login session management endpoints
	OAuth2Clients  string // OAuth2 client management endpoints (admin)
	External       string // External provider authentication endpoints
}

// DefaultV1Prefixes returns the default v1 prefix configuration.
// This is the recommended configuration that resolves the 2FA prefix inconsistency.
//
// Pattern: /api/v1/idm/* for IDM endpoints, /api/v1/oauth2 for OAuth2 standard endpoints
func DefaultV1Prefixes() PrefixConfig {
	return PrefixConfig{
		Auth:          "/api/v1/idm/auth",
		Signup:        "/api/v1/idm/signup",
		Profile:       "/api/v1/idm/profile",
		TwoFA:         "/api/v1/idm/2fa", // Fixed from /idm/2fa
		Email:         "/api/v1/idm/email",
		PasswordReset: "/api/v1/idm/password-reset",
		OAuth2:        "/api/v1/oauth2",
		Users:         "/api/v1/idm/users",
		Roles:         "/api/v1/idm/roles",
		Device:        "/api/v1/idm/device",
		Logins:        "/api/v1/idm/logins",
		OAuth2Clients: "/api/v1/idm/oauth2-clients",
		External:      "/api/v1/idm/external",
	}
}

// LegacyPrefixes returns the legacy prefix configuration for backward compatibility.
// This includes the inconsistent 2FA prefix /idm/2fa (missing /api prefix).
//
// DEPRECATED: Use DefaultV1Prefixes() or custom configuration instead.
func LegacyPrefixes() PrefixConfig {
	return PrefixConfig{
		Auth:          "/api/idm/auth",
		Signup:        "/api/idm/signup",
		Profile:       "/api/idm/profile",
		TwoFA:         "/idm/2fa", // Inconsistent - missing /api prefix
		Email:         "/api/idm/email",
		PasswordReset: "/api/idm/password-reset",
		OAuth2:        "/api/oauth2",
		Users:         "/api/idm/users",
		Roles:         "/api/idm/roles",
		Device:        "/api/idm/device",
		Logins:        "/api/idm/logins",
		OAuth2Clients: "/api/idm/oauth2-clients",
		External:      "/api/idm/external",
	}
}

// BuildPrefixesFromBase builds prefix configuration from a base path.
//
// Appends route segments to the base path for each route group.
// This provides a simple way to configure all endpoints with one prefix.
//
// Example:
//
//	BuildPrefixesFromBase("/api/v1/idm")
//	// Returns:
//	// PrefixConfig{
//	//   Auth:          "/api/v1/idm/auth",
//	//   Signup:        "/api/v1/idm/signup",
//	//   Profile:       "/api/v1/idm/profile",
//	//   TwoFA:         "/api/v1/idm/2fa",
//	//   Email:         "/api/v1/idm/email",
//	//   PasswordReset: "/api/v1/idm/password-reset",
//	//   OAuth2:        "/api/v1/idm/oauth2",
//	//   ...
//	// }
func BuildPrefixesFromBase(basePath string) PrefixConfig {
	// Remove trailing slash if present
	if len(basePath) > 0 && basePath[len(basePath)-1] == '/' {
		basePath = basePath[:len(basePath)-1]
	}

	return PrefixConfig{
		Auth:          basePath + "/auth",
		Signup:        basePath + "/signup",
		Profile:       basePath + "/profile",
		TwoFA:         basePath + "/2fa",
		Email:         basePath + "/email",
		PasswordReset: basePath + "/password-reset",
		OAuth2:        basePath + "/oauth2",
		Users:         basePath + "/users",
		Roles:         basePath + "/roles",
		Device:        basePath + "/device",
		Logins:        basePath + "/logins",
		OAuth2Clients: basePath + "/oauth2-clients",
		External:      basePath + "/external",
	}
}

// LoadPrefixConfig loads prefix configuration from environment variables.
// Falls back to DefaultV1Prefixes() for any unset variables.
//
// Configuration priority (highest to lowest):
//   1. API_PREFIX_BASE: Base path for all endpoints (simplest)
//   2. API_PREFIX_LEGACY: Use legacy prefix pattern
//   3. Individual API_PREFIX_* overrides
//   4. DefaultV1Prefixes (default)
//
// Environment variables:
//   - API_PREFIX_BASE: Base path for all endpoints (e.g., "/api/v1/idm")
//   - API_PREFIX_LEGACY: Set to "true" to use legacy prefix pattern
//   - API_PREFIX_AUTH: Authentication endpoint prefix (overrides base)
//   - API_PREFIX_SIGNUP: Signup endpoint prefix (overrides base)
//   - API_PREFIX_PROFILE: Profile endpoint prefix (overrides base)
//   - API_PREFIX_2FA: Two-factor auth endpoint prefix (overrides base)
//   - API_PREFIX_EMAIL: Email verification endpoint prefix (overrides base)
//   - API_PREFIX_PASSWORD_RESET: Password reset endpoint prefix (overrides base)
//   - API_PREFIX_OAUTH2: OAuth2 endpoint prefix (overrides base)
//   - API_PREFIX_USERS: User management endpoint prefix (overrides base)
//   - API_PREFIX_ROLES: Role management endpoint prefix (overrides base)
//   - API_PREFIX_DEVICE: Device management endpoint prefix (overrides base)
//   - API_PREFIX_LOGINS: Login session endpoint prefix (overrides base)
//   - API_PREFIX_OAUTH2_CLIENTS: OAuth2 client management endpoint prefix (overrides base)
//   - API_PREFIX_EXTERNAL: External provider endpoint prefix (overrides base)
func LoadPrefixConfig() PrefixConfig {
	var defaults PrefixConfig

	// Priority 1: Base prefix (simplest - one prefix for all routes)
	if basePath := GetEnv("API_PREFIX_BASE"); basePath != "" {
		defaults = BuildPrefixesFromBase(basePath)
	} else if GetEnvBool("API_PREFIX_LEGACY", false) {
		// Priority 2: Legacy mode
		defaults = LegacyPrefixes()
	} else {
		// Priority 3: Use v1 defaults
		defaults = DefaultV1Prefixes()
	}

	// Merge individual overrides (allows overriding specific routes)
	return mergeWithDefaults(defaults)
}

// mergeWithDefaults merges environment variable overrides with defaults
func mergeWithDefaults(defaults PrefixConfig) PrefixConfig {
	return PrefixConfig{
		Auth:          GetEnvOrDefault("API_PREFIX_AUTH", defaults.Auth),
		Signup:        GetEnvOrDefault("API_PREFIX_SIGNUP", defaults.Signup),
		Profile:       GetEnvOrDefault("API_PREFIX_PROFILE", defaults.Profile),
		TwoFA:         GetEnvOrDefault("API_PREFIX_2FA", defaults.TwoFA),
		Email:         GetEnvOrDefault("API_PREFIX_EMAIL", defaults.Email),
		PasswordReset: GetEnvOrDefault("API_PREFIX_PASSWORD_RESET", defaults.PasswordReset),
		OAuth2:        GetEnvOrDefault("API_PREFIX_OAUTH2", defaults.OAuth2),
		Users:         GetEnvOrDefault("API_PREFIX_USERS", defaults.Users),
		Roles:         GetEnvOrDefault("API_PREFIX_ROLES", defaults.Roles),
		Device:        GetEnvOrDefault("API_PREFIX_DEVICE", defaults.Device),
		Logins:        GetEnvOrDefault("API_PREFIX_LOGINS", defaults.Logins),
		OAuth2Clients: GetEnvOrDefault("API_PREFIX_OAUTH2_CLIENTS", defaults.OAuth2Clients),
		External:      GetEnvOrDefault("API_PREFIX_EXTERNAL", defaults.External),
	}
}

// Validate checks that all prefix paths are valid (non-empty and start with /)
func (p PrefixConfig) Validate() error {
	prefixes := map[string]string{
		"Auth":          p.Auth,
		"Signup":        p.Signup,
		"Profile":       p.Profile,
		"TwoFA":         p.TwoFA,
		"Email":         p.Email,
		"PasswordReset": p.PasswordReset,
		"OAuth2":        p.OAuth2,
		"Users":         p.Users,
		"Roles":         p.Roles,
		"Device":        p.Device,
		"Logins":        p.Logins,
		"OAuth2Clients": p.OAuth2Clients,
		"External":      p.External,
	}

	for name, prefix := range prefixes {
		if prefix == "" {
			return fmt.Errorf("prefix configuration missing: %s", name)
		}
		if prefix[0] != '/' {
			return fmt.Errorf("prefix must start with '/': %s = %s", name, prefix)
		}
	}

	return nil
}
