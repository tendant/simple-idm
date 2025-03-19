package token

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// JwtConfig holds JWT service configuration
type JwtConfig struct {
	Secret         string
	CookieHttpOnly bool
	CookieSecure   bool
	TokenGenerator TokenGenerator
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

// WithTokenGenerator sets the TokenGenerator
func WithTokenGenerator(generator TokenGenerator) JwtOption {
	return func(config *JwtConfig) {
		config.TokenGenerator = generator
	}
}

// NewJwtConfig creates a new JwtConfig with the given secret and options
func NewJwtConfig(secret string, opts ...JwtOption) *JwtConfig {
	config := &JwtConfig{
		Secret:         secret,
		CookieHttpOnly: true,
		CookieSecure:   true,
	}

	// Apply options
	for _, opt := range opts {
		opt(config)
	}

	// If no token generator is set, create a default one
	if config.TokenGenerator == nil {
		tokenConfig := TokenGeneratorConfig{
			Secret:          secret,
			SigningMethod:   jwt.SigningMethodHS256,
			DefaultIssuer:   APPLICATION_NAME,
			DefaultAudience: APPLICATION_NAME,
			CookieHttpOnly:  config.CookieHttpOnly,
			CookieSecure:    config.CookieSecure,
			CookiePath:      "/",
			CookieSameSite:  http.SameSiteLaxMode,
		}
		config.TokenGenerator = NewTokenGenerator(tokenConfig)
	}

	return config
}

// convertClaims converts an interface{} to a map[string]interface{} for use in tokens
// If the input is already a map[string]interface{}, it is used directly
// Otherwise, it wraps the input in a map with a "data" key
func convertClaims(claims interface{}) map[string]interface{} {
	if claims == nil {
		return nil
	}

	extraClaims, ok := claims.(map[string]interface{})
	if !ok {
		// If claims is not already a map[string]interface{}, create a new map with a single entry
		extraClaims = map[string]interface{}{"data": claims}
	}

	return extraClaims
}

// GenerateAndSetAccessCookie generates an access token and sets it as a cookie
func (c *JwtConfig) GenerateAndSetAccessCookie(w http.ResponseWriter, subject string, claims interface{}) (string, error) {
	extraClaims := convertClaims(claims)

	token, expiry, err := c.TokenGenerator.GenerateToken(subject, DefaultAccessTokenExpiry, nil, extraClaims)
	if err != nil {
		return "", err
	}

	err = c.TokenGenerator.SetCookie(w, ACCESS_TOKEN_NAME, token, expiry)
	if err != nil {
		return "", err
	}

	return token, nil
}

// GenerateAndSetRefreshCookie generates a refresh token and sets it as a cookie
func (c *JwtConfig) GenerateAndSetRefreshCookie(w http.ResponseWriter, subject string, claims interface{}) (string, error) {
	extraClaims := convertClaims(claims)

	token, expiry, err := c.TokenGenerator.GenerateToken(subject, DefaultRefreshTokenExpiry, nil, extraClaims)
	if err != nil {
		return "", err
	}

	err = c.TokenGenerator.SetCookie(w, REFRESH_TOKEN_NAME, token, expiry)
	if err != nil {
		return "", err
	}

	return token, nil
}

// GenerateAndSetTempCookie generates a temporary token and sets it as a cookie
func (c *JwtConfig) GenerateAndSetTempCookie(w http.ResponseWriter, subject string, claims interface{}) (string, error) {
	extraClaims := convertClaims(claims)

	token, expiry, err := c.TokenGenerator.GenerateToken(subject, DefaultTempTokenExpiry, nil, extraClaims)
	if err != nil {
		return "", err
	}

	err = c.TokenGenerator.SetCookie(w, ACCESS_TOKEN_NAME, token, expiry)
	if err != nil {
		return "", err
	}

	return token, nil
}

// GenerateAndSetPasswordResetCookie generates a password reset token and sets it as a cookie
func (c *JwtConfig) GenerateAndSetPasswordResetCookie(w http.ResponseWriter, subject string, claims interface{}) (string, error) {
	extraClaims := convertClaims(claims)

	token, expiry, err := c.TokenGenerator.GenerateToken(subject, DefaultPasswordResetExpiry, nil, extraClaims)
	if err != nil {
		return "", err
	}

	err = c.TokenGenerator.SetCookie(w, PASSWORD_RESET_TOKEN_NAME, token, expiry)
	if err != nil {
		return "", err
	}

	return token, nil
}

// GenerateAndSetLogoutCookie generates a logout token and sets it as a cookie for the specified cookie name
func (c *JwtConfig) GenerateAndSetLogoutCookie(w http.ResponseWriter, cookieName string) (string, error) {
	token, expiry, err := c.TokenGenerator.GenerateToken(APPLICATION_NAME, DefaultLogoutTokenExpiry, nil, nil)
	if err != nil {
		return "", err
	}

	err = c.TokenGenerator.SetCookie(w, cookieName, token, expiry)
	if err != nil {
		return "", err
	}

	return token, nil
}
