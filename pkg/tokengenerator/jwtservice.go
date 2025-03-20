package tokengenerator

import (
	"time"

	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Token type constants
const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
	LOGOUT_TOKEN_NAME  = "logout_token"
)

// Default token expiry durations
const (
	DefaultAccessTokenExpiry  = 15 * time.Minute
	DefaultRefreshTokenExpiry = 24 * time.Hour
	DefaultTempTokenExpiry    = 5 * time.Minute
	DefaultLogoutTokenExpiry  = 1 * time.Second
)

// JwtService provides JWT token generation and cookie management
type JwtService struct {
	TokenGenerator TokenGenerator
	CookieSetter   CookieSetter

	// Configurable token expiry durations
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	TempTokenExpiry    time.Duration
	LogoutTokenExpiry  time.Duration

	Subject string
}

// JwtServiceOption is a function that configures a JwtService
type JwtServiceOption func(*JwtService)

// WithTokenGenerator sets the token generator
func WithTokenGenerator(tokenGenerator TokenGenerator) JwtServiceOption {
	return func(js *JwtService) {
		js.TokenGenerator = tokenGenerator
	}
}

// WithCookieSetter sets the cookie setter
func WithCookieSetter(cookieSetter CookieSetter) JwtServiceOption {
	return func(js *JwtService) {
		js.CookieSetter = cookieSetter
	}
}

// WithAccessTokenExpiry sets the access token expiry duration
func WithAccessTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *JwtService) {
		js.AccessTokenExpiry = expiry
	}
}

// WithRefreshTokenExpiry sets the refresh token expiry duration
func WithRefreshTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *JwtService) {
		js.RefreshTokenExpiry = expiry
	}
}

// WithTempTokenExpiry sets the temporary token expiry duration
func WithTempTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *JwtService) {
		js.TempTokenExpiry = expiry
	}
}

// WithLogoutTokenExpiry sets the logout token expiry duration
func WithLogoutTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *JwtService) {
		js.LogoutTokenExpiry = expiry
	}
}

// WithSubject sets the default subject for tokens
func WithSubject(subject string) JwtServiceOption {
	return func(js *JwtService) {
		js.Subject = subject
	}
}

// NewJwtService creates a new JwtService
func NewJwtService(opts ...JwtServiceOption) *JwtService {
	js := &JwtService{
		// Initialize with default values
		AccessTokenExpiry:  DefaultAccessTokenExpiry,
		RefreshTokenExpiry: DefaultRefreshTokenExpiry,
		TempTokenExpiry:    DefaultTempTokenExpiry,
		LogoutTokenExpiry:  DefaultLogoutTokenExpiry,
	}

	for _, opt := range opts {
		opt(js)
	}

	return js
}

// GenerateToken generates a token with the given parameters
func (js *JwtService) GenerateToken(tokenName, subject string, extraClaims map[string]interface{}) (string, time.Time, error) {
	var expiry time.Duration

	// If subject is empty, use the default subject if available
	if subject == "" && js.Subject != "" {
		subject = js.Subject
	}

	switch tokenName {
	case ACCESS_TOKEN_NAME:
		expiry = js.AccessTokenExpiry
	case REFRESH_TOKEN_NAME:
		expiry = js.RefreshTokenExpiry
	case TEMP_TOKEN_NAME:
		expiry = js.TempTokenExpiry
	case LOGOUT_TOKEN_NAME:
		expiry = js.LogoutTokenExpiry
	default:
		expiry = js.AccessTokenExpiry
	}

	tokenStr, expiryTime, err := js.TokenGenerator.GenerateToken(subject, expiry, nil, extraClaims)
	return tokenStr, expiryTime, err
}

// ParseToken parses and validates a token
func (js *JwtService) ParseToken(tokenName, tokenStr string) (*jwt.Token, error) {
	return js.TokenGenerator.ParseToken(tokenStr)
}

// GenerateAccessToken generates an access token
func (js *JwtService) GenerateAccessToken(subject string, extraClaims map[string]interface{}) (string, time.Time, error) {
	return js.GenerateToken(ACCESS_TOKEN_NAME, subject, extraClaims)
}

// GenerateRefreshToken generates a refresh token
func (js *JwtService) GenerateRefreshToken(subject string, extraClaims map[string]interface{}) (string, time.Time, error) {
	return js.GenerateToken(REFRESH_TOKEN_NAME, subject, extraClaims)
}

// GenerateTempToken generates a temporary token
func (js *JwtService) GenerateTempToken(subject string, extraClaims map[string]interface{}) (string, time.Time, error) {
	return js.GenerateToken(TEMP_TOKEN_NAME, subject, extraClaims)
}

// GenerateLogoutToken generates a logout token
func (js *JwtService) GenerateLogoutToken(subject string, extraClaims map[string]interface{}) (string, time.Time, error) {
	return js.GenerateToken(LOGOUT_TOKEN_NAME, subject, extraClaims)
}

// SetAccessTokenCookie generates an access token and sets it as a cookie
func (js *JwtService) SetAccessTokenCookie(w http.ResponseWriter, tokenValue string, expire time.Time) error {
	return js.CookieSetter.SetCookie(w, ACCESS_TOKEN_NAME, tokenValue, expire)
}

// SetRefreshTokenCookie generates a refresh token and sets it as a cookie
func (js *JwtService) SetRefreshTokenCookie(w http.ResponseWriter, tokenValue string, expire time.Time) error {
	return js.CookieSetter.SetCookie(w, REFRESH_TOKEN_NAME, tokenValue, expire)
}

// SetTempTokenCookie generates a temporary token and sets it as a cookie
func (js *JwtService) SetTempTokenCookie(w http.ResponseWriter, tokenValue string, expire time.Time) error {
	return js.CookieSetter.SetCookie(w, TEMP_TOKEN_NAME, tokenValue, expire)
}

// SetLogoutTokenCookie generates a logout token and sets it as a cookie
func (js *JwtService) SetLogoutTokenCookie(w http.ResponseWriter, tokenValue string, expire time.Time) error {
	return js.CookieSetter.SetCookie(w, LOGOUT_TOKEN_NAME, tokenValue, expire)
}

// GenerateAndSetCookie is a convenience method that generates a token and sets it as a cookie
func (js *JwtService) GenerateAndSetCookie(w http.ResponseWriter, tokenName string, subject string, extraClaims map[string]interface{}) error {
	token, expiry, err := js.GenerateToken(tokenName, subject, extraClaims)
	if err != nil {
		return err
	}
	return js.CookieSetter.SetCookie(w, tokenName, token, expiry)
}
