package token

// JwtConfig holds JWT service configuration
type JwtConfig struct {
	Secret         string
	CookieHttpOnly bool
	CookieSecure   bool
}

// JwtOption defines a function type for configuring JwtConfig
type JwtOption func(*JwtConfig)

// WithCookieHttpOnly sets the HttpOnly flag for cookies
func WithCookieHttpOnly(httpOnly bool) JwtOption {
	return func(config *JwtConfig) {
		config.CookieHttpOnly = httpOnly
	}
}

// WithCookieSecure sets the Secure flag for cookies
func WithCookieSecure(secure bool) JwtOption {
	return func(config *JwtConfig) {
		config.CookieSecure = secure
	}
}

// NewJwtConfig creates a new JwtConfig with the given secret and options
func NewJwtConfig(secret string, opts ...JwtOption) *JwtConfig {
	config := &JwtConfig{Secret: secret}

	for _, opt := range opts {
		opt(config)
	}

	return config
}
