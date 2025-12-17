package config

// JWKSConfig contains RSA key settings for JWT signing.
// Fields have no env tags - populate manually or use NewJWKSConfigFromEnv() for standard env var names.
type JWKSConfig struct {
	// KeyID is the key identifier for the JWKS key (kid claim)
	KeyID string

	// Algorithm is the signing algorithm (typically "RS256")
	Algorithm string

	// PrivateKeyFile is the path to the RSA private key PEM file
	PrivateKeyFile string
}

// DefaultJWKSConfig returns a JWKSConfig with sensible defaults
func DefaultJWKSConfig() JWKSConfig {
	return JWKSConfig{
		KeyID:          "",
		Algorithm:      "RS256",
		PrivateKeyFile: "jwt-private.pem",
	}
}

// NewJWKSConfigFromEnv loads JWKSConfig from standard environment variables.
// This is an optional convenience function - you can also populate the struct manually.
//
// Environment variables:
//   - JWKS_KEY_ID: Key identifier for the JWKS key (default: "")
//   - JWKS_ALGORITHM: Signing algorithm (default: "RS256")
//   - JWKS_PRIVATE_KEY_FILE: Path to RSA private key PEM file (default: "jwt-private.pem")
func NewJWKSConfigFromEnv() JWKSConfig {
	return JWKSConfig{
		KeyID:          GetEnvOrDefault("JWKS_KEY_ID", ""),
		Algorithm:      GetEnvOrDefault("JWKS_ALGORITHM", "RS256"),
		PrivateKeyFile: GetEnvOrDefault("JWKS_PRIVATE_KEY_FILE", "jwt-private.pem"),
	}
}

// IsConfigured returns true if the JWKS config has a private key file specified
func (c *JWKSConfig) IsConfigured() bool {
	return c.PrivateKeyFile != ""
}
