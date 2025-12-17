package config

// OAuth2ClientConfig contains OAuth2 client encryption settings.
// Fields have no env tags - populate manually or use NewOAuth2ClientConfigFromEnv() for standard env var names.
type OAuth2ClientConfig struct {
	// EncryptionKey is the key used to encrypt OAuth2 client secrets.
	// Must be 32 bytes base64 encoded for AES-256 encryption.
	EncryptionKey string
}

// DefaultOAuth2ClientConfig returns an OAuth2ClientConfig with sensible defaults.
// Note: The encryption key should be set in production.
func DefaultOAuth2ClientConfig() OAuth2ClientConfig {
	return OAuth2ClientConfig{
		EncryptionKey: "",
	}
}

// NewOAuth2ClientConfigFromEnv loads OAuth2ClientConfig from standard environment variables.
// This is an optional convenience function - you can also populate the struct manually.
//
// Environment variables:
//   - OAUTH2_CLIENT_ENCRYPTION_KEY: Base64-encoded 32-byte key for client secret encryption
func NewOAuth2ClientConfigFromEnv() OAuth2ClientConfig {
	return OAuth2ClientConfig{
		EncryptionKey: GetEnv("OAUTH2_CLIENT_ENCRYPTION_KEY"),
	}
}

// IsConfigured returns true if the encryption key is set
func (c *OAuth2ClientConfig) IsConfigured() bool {
	return c.EncryptionKey != ""
}
