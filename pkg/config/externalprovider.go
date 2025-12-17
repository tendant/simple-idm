package config

// ExternalProviderConfig contains OAuth2 external provider settings.
// Fields have no env tags - populate manually or use NewExternalProviderConfigFromEnv() for standard env var names.
type ExternalProviderConfig struct {
	// Google OAuth2
	GoogleClientID     string
	GoogleClientSecret string
	GoogleEnabled      bool

	// Microsoft OAuth2
	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftEnabled      bool

	// GitHub OAuth2
	GitHubClientID     string
	GitHubClientSecret string
	GitHubEnabled      bool

	// LinkedIn OAuth2
	LinkedInClientID     string
	LinkedInClientSecret string
	LinkedInEnabled      bool

	// DefaultRole is the role assigned to users created via external providers
	DefaultRole string
}

// DefaultExternalProviderConfig returns an ExternalProviderConfig with sensible defaults.
// All providers are disabled by default.
func DefaultExternalProviderConfig() ExternalProviderConfig {
	return ExternalProviderConfig{
		GoogleEnabled:    false,
		MicrosoftEnabled: false,
		GitHubEnabled:    false,
		LinkedInEnabled:  false,
		DefaultRole:      "user",
	}
}

// NewExternalProviderConfigFromEnv loads ExternalProviderConfig from standard environment variables.
// This is an optional convenience function - you can also populate the struct manually.
//
// Environment variables:
//   - GOOGLE_CLIENT_ID: Google OAuth2 client ID
//   - GOOGLE_CLIENT_SECRET: Google OAuth2 client secret
//   - GOOGLE_ENABLED: Enable Google OAuth2 provider (default: false)
//   - MICROSOFT_CLIENT_ID: Microsoft OAuth2 client ID
//   - MICROSOFT_CLIENT_SECRET: Microsoft OAuth2 client secret
//   - MICROSOFT_ENABLED: Enable Microsoft OAuth2 provider (default: false)
//   - GITHUB_CLIENT_ID: GitHub OAuth2 client ID
//   - GITHUB_CLIENT_SECRET: GitHub OAuth2 client secret
//   - GITHUB_ENABLED: Enable GitHub OAuth2 provider (default: false)
//   - LINKEDIN_CLIENT_ID: LinkedIn OAuth2 client ID
//   - LINKEDIN_CLIENT_SECRET: LinkedIn OAuth2 client secret
//   - LINKEDIN_ENABLED: Enable LinkedIn OAuth2 provider (default: false)
//   - EXTERNAL_PROVIDER_DEFAULT_ROLE: Default role for users created via external providers (default: "user")
func NewExternalProviderConfigFromEnv() ExternalProviderConfig {
	return ExternalProviderConfig{
		GoogleClientID:        GetEnv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:    GetEnv("GOOGLE_CLIENT_SECRET"),
		GoogleEnabled:         GetEnvBool("GOOGLE_ENABLED", false),
		MicrosoftClientID:     GetEnv("MICROSOFT_CLIENT_ID"),
		MicrosoftClientSecret: GetEnv("MICROSOFT_CLIENT_SECRET"),
		MicrosoftEnabled:      GetEnvBool("MICROSOFT_ENABLED", false),
		GitHubClientID:        GetEnv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:    GetEnv("GITHUB_CLIENT_SECRET"),
		GitHubEnabled:         GetEnvBool("GITHUB_ENABLED", false),
		LinkedInClientID:      GetEnv("LINKEDIN_CLIENT_ID"),
		LinkedInClientSecret:  GetEnv("LINKEDIN_CLIENT_SECRET"),
		LinkedInEnabled:       GetEnvBool("LINKEDIN_ENABLED", false),
		DefaultRole:           GetEnvOrDefault("EXTERNAL_PROVIDER_DEFAULT_ROLE", "user"),
	}
}

// IsGoogleConfigured returns true if Google OAuth2 is enabled and credentials are set
func (c *ExternalProviderConfig) IsGoogleConfigured() bool {
	return c.GoogleEnabled && c.GoogleClientID != "" && c.GoogleClientSecret != ""
}

// IsMicrosoftConfigured returns true if Microsoft OAuth2 is enabled and credentials are set
func (c *ExternalProviderConfig) IsMicrosoftConfigured() bool {
	return c.MicrosoftEnabled && c.MicrosoftClientID != "" && c.MicrosoftClientSecret != ""
}

// IsGitHubConfigured returns true if GitHub OAuth2 is enabled and credentials are set
func (c *ExternalProviderConfig) IsGitHubConfigured() bool {
	return c.GitHubEnabled && c.GitHubClientID != "" && c.GitHubClientSecret != ""
}

// IsLinkedInConfigured returns true if LinkedIn OAuth2 is enabled and credentials are set
func (c *ExternalProviderConfig) IsLinkedInConfigured() bool {
	return c.LinkedInEnabled && c.LinkedInClientID != "" && c.LinkedInClientSecret != ""
}

// HasAnyProviderConfigured returns true if at least one external provider is configured
func (c *ExternalProviderConfig) HasAnyProviderConfigured() bool {
	return c.IsGoogleConfigured() || c.IsMicrosoftConfigured() || c.IsGitHubConfigured() || c.IsLinkedInConfigured()
}
