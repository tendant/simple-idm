package token

// JwtConfig holds JWT service configuration
type JwtConfig struct {
	Secret                    string
	CookieHttpOnly            bool
	CookieSecure              bool
	AccessTokenService        TokenService
	RefreshTokenService       TokenService
	PasswordResetTokenService TokenService
	LogoutTokenService        TokenService
	TempTokenService          TokenService
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

// WithAccessTokenService sets the AccessTokenService
func WithAccessTokenService(service TokenService) JwtOption {
	return func(config *JwtConfig) {
		config.AccessTokenService = service
	}
}

// WithRefreshTokenService sets the RefreshTokenService
func WithRefreshTokenService(service TokenService) JwtOption {
	return func(config *JwtConfig) {
		config.RefreshTokenService = service
	}
}

// WithPasswordResetTokenService sets the PasswordResetTokenService
func WithPasswordResetTokenService(service TokenService) JwtOption {
	return func(config *JwtConfig) {
		config.PasswordResetTokenService = service
	}
}

// WithLogoutTokenService sets the LogoutTokenService
func WithLogoutTokenService(service TokenService) JwtOption {
	return func(config *JwtConfig) {
		config.LogoutTokenService = service
	}
}

// WithTempTokenService sets the TempTokenService
func WithTempTokenService(service TokenService) JwtOption {
	return func(config *JwtConfig) {
		config.TempTokenService = service
	}
}

// NewJwtConfig creates a new JwtConfig with the given secret and options
func NewJwtConfig(secret string, opts ...JwtOption) *JwtConfig {
	config := &JwtConfig{
		Secret: secret,
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}
