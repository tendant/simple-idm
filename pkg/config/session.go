package config

// SessionManagementConfig contains session tracking settings.
// Fields have no env tags - populate manually or use NewSessionManagementConfigFromEnv() for standard env var names.
type SessionManagementConfig struct {
	// Enabled controls whether session tracking and management is active
	Enabled bool

	// APIPrefix is the endpoint prefix for session management routes.
	// If empty, defaults to the IDM prefix + "/sessions".
	APIPrefix string
}

// DefaultSessionManagementConfig returns a SessionManagementConfig with sensible defaults
func DefaultSessionManagementConfig() SessionManagementConfig {
	return SessionManagementConfig{
		Enabled:   false,
		APIPrefix: "",
	}
}

// NewSessionManagementConfigFromEnv loads SessionManagementConfig from standard environment variables.
// This is an optional convenience function - you can also populate the struct manually.
//
// Environment variables:
//   - SESSION_MANAGEMENT_ENABLED: Enable session tracking and management (default: false)
//   - SESSION_MANAGEMENT_API_PREFIX: API endpoint prefix for session routes (default: "")
func NewSessionManagementConfigFromEnv() SessionManagementConfig {
	return SessionManagementConfig{
		Enabled:   GetEnvBool("SESSION_MANAGEMENT_ENABLED", false),
		APIPrefix: GetEnvOrDefault("SESSION_MANAGEMENT_API_PREFIX", ""),
	}
}
