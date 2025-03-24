package tokengenerator

import (
	"fmt"
	"net/http"
	"time"

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
	DefaultAccessTokenExpiry  = 5 * time.Minute
	DefaultRefreshTokenExpiry = 15 * time.Minute
	DefaultTempTokenExpiry    = 1 * time.Minute
	DefaultLogoutTokenExpiry  = -1 * time.Second
)

// JwtService defines the interface for JWT token generation and management
type JwtService interface {
	// Token generator management
	GetTokenGenerator(tokenName string) TokenGenerator
	GenerateToken(tokenName, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error)

	// Token generation methods
	GenerateTokensAndSetCookie(w http.ResponseWriter, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) error
	GenerateTempTokenAndSetCookie(w http.ResponseWriter, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, error)
	GenerateLogoutTokenAndSetCookie(w http.ResponseWriter, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, error)

	// Token parsing and validation
	ParseToken(tokenName, tokenValue string) (*jwt.Token, error)

	// User ID extraction
	GetUserIDFromClaims(claims jwt.Claims) (string, error)
	GetLoginIDFromClaims(claims jwt.Claims) (string, error)

	// Cookie management
	SetCookie(w http.ResponseWriter, cookieName, cookieValue string, expire time.Time) error
	ClearCookie(w http.ResponseWriter, tokenName string) error
}

// DefaultJwtService provides the default implementation of the JwtService interface
type DefaultJwtService struct {
	TokenGenerators       map[string]TokenGenerator
	DefaultTokenGenerator TokenGenerator
	CookieSetters         map[string]CookieSetter
	DefaultCookieSetter   CookieSetter

	// Configurable token expiry durations
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	TempTokenExpiry    time.Duration
	LogoutTokenExpiry  time.Duration
}

// JwtServiceOption is a function that configures a DefaultJwtService
type JwtServiceOption func(*DefaultJwtService)

// WithTokenGenerator sets the token generator for a specific token name
func WithTokenGenerator(tokenName string, tokenGenerator TokenGenerator) JwtServiceOption {
	return func(js *DefaultJwtService) {
		if js.TokenGenerators == nil {
			js.TokenGenerators = make(map[string]TokenGenerator)
		}
		js.TokenGenerators[tokenName] = tokenGenerator
	}
}

// WithCookieSetter sets the cookie setter for a specific cookie name
func WithCookieSetter(cookieName string, cookieSetter CookieSetter) JwtServiceOption {
	return func(js *DefaultJwtService) {
		if js.CookieSetters == nil {
			js.CookieSetters = make(map[string]CookieSetter)
		}
		js.CookieSetters[cookieName] = cookieSetter
	}
}

// WithDefaultCookieSetter sets the default cookie setter
func WithDefaultCookieSetter(cookieSetter CookieSetter) JwtServiceOption {
	return func(js *DefaultJwtService) {
		js.DefaultCookieSetter = cookieSetter
	}
}

// WithAccessTokenExpiry sets the access token expiry duration
func WithAccessTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *DefaultJwtService) {
		js.AccessTokenExpiry = expiry
	}
}

// WithRefreshTokenExpiry sets the refresh token expiry duration
func WithRefreshTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *DefaultJwtService) {
		js.RefreshTokenExpiry = expiry
	}
}

// WithTempTokenExpiry sets the temporary token expiry duration
func WithTempTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *DefaultJwtService) {
		js.TempTokenExpiry = expiry
	}
}

// WithLogoutTokenExpiry sets the logout token expiry duration
func WithLogoutTokenExpiry(expiry time.Duration) JwtServiceOption {
	return func(js *DefaultJwtService) {
		js.LogoutTokenExpiry = expiry
	}
}

// NewJwtService creates a new DefaultJwtService
func NewJwtService(tokenGenerator TokenGenerator, options ...JwtServiceOption) JwtService {
	js := &DefaultJwtService{
		TokenGenerators:       make(map[string]TokenGenerator),
		DefaultTokenGenerator: tokenGenerator,
		CookieSetters:         make(map[string]CookieSetter),
		DefaultCookieSetter:   NewCookieSetter(true, true),
		AccessTokenExpiry:     DefaultAccessTokenExpiry,
		RefreshTokenExpiry:    DefaultRefreshTokenExpiry,
		TempTokenExpiry:       DefaultTempTokenExpiry,
		LogoutTokenExpiry:     DefaultLogoutTokenExpiry,
	}

	for _, option := range options {
		option(js)
	}

	return js
}

// GenerateToken generates a token with the given parameters
func (js *DefaultJwtService) GenerateToken(tokenName, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error) {
	var expiry time.Duration
	var tokenGenerator TokenGenerator

	tokenGenerator, ok := js.TokenGenerators[tokenName]
	if !ok {
		tokenGenerator = js.DefaultTokenGenerator
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

	tokenStr, expiryTime, err := tokenGenerator.GenerateToken(subject, expiry, rootModifications, extraClaims)
	return tokenStr, expiryTime, err
}

func (js *DefaultJwtService) GenerateTokensAndSetCookie(w http.ResponseWriter, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) error {
	tokenName := ACCESS_TOKEN_NAME
	token, expiry, err := js.GenerateToken(tokenName, subject, rootModifications, extraClaims)
	if err != nil {
		return fmt.Errorf("failed to generate %s token: %w", tokenName, err)
	}

	err = js.SetCookie(w, tokenName, token, expiry)
	if err != nil {
		return fmt.Errorf("failed to set %s cookie: %w", tokenName, err)
	}

	tokenName = REFRESH_TOKEN_NAME
	token, expiry, err = js.GenerateToken(tokenName, subject, rootModifications, extraClaims)
	if err != nil {
		return fmt.Errorf("failed to generate %s token: %w", tokenName, err)
	}

	err = js.SetCookie(w, tokenName, token, expiry)
	if err != nil {
		return fmt.Errorf("failed to set %s cookie: %w", tokenName, err)
	}

	return nil
}

// GenerateTempTokenAndSetCookie generates a token and sets it as a cookie
func (js *DefaultJwtService) GenerateTempTokenAndSetCookie(w http.ResponseWriter, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, error) {
	token, expiry, err := js.GenerateToken(TEMP_TOKEN_NAME, subject, rootModifications, extraClaims)
	if err != nil {
		return "", fmt.Errorf("failed to generate %s token: %w", TEMP_TOKEN_NAME, err)
	}

	err = js.SetCookie(w, TEMP_TOKEN_NAME, token, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to set %s cookie: %w", TEMP_TOKEN_NAME, err)
	}
	return token, nil
}

// GenerateLogoutTokenAndSetCookie generates a token and sets it as a cookie
func (js *DefaultJwtService) GenerateLogoutTokenAndSetCookie(w http.ResponseWriter, subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, error) {
	token, expiry, err := js.GenerateToken(LOGOUT_TOKEN_NAME, subject, rootModifications, extraClaims)
	if err != nil {
		return "", fmt.Errorf("failed to generate %s token: %w", LOGOUT_TOKEN_NAME, err)
	}

	err = js.SetCookie(w, LOGOUT_TOKEN_NAME, token, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to set %s cookie: %w", LOGOUT_TOKEN_NAME, err)
	}
	return token, nil
}

// ParseToken parses and validates a token
func (js *DefaultJwtService) ParseToken(tokenName, tokenStr string) (*jwt.Token, error) {
	tokenGenerator := js.GetTokenGenerator(tokenName)
	return tokenGenerator.ParseToken(tokenStr)
}

// GetUserIDFromClaims extracts the user ID from token claims
func (js *DefaultJwtService) GetUserIDFromClaims(claims jwt.Claims) (string, error) {
	// First try to get from subject
	subject, err := claims.GetSubject()
	if err == nil && subject != "" {
		return subject, nil
	}

	// If subject is empty or not available, try to get from extra claims
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return "", fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("extra_claims has invalid format")
	}

	// Try user_id first, then fall back to other common ID field names
	for _, field := range []string{"user_id", "user_uuid", "userId", "id", "sub"} {
		if idValue, ok := extraClaims[field]; ok {
			if idStr, ok := idValue.(string); ok && idStr != "" {
				return idStr, nil
			}
		}
	}

	return "", fmt.Errorf("user ID not found in token claims")
}

// GetLoginIDFromClaims extracts the login ID from token claims
func (js *DefaultJwtService) GetLoginIDFromClaims(claims jwt.Claims) (string, error) {
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return "", fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("extra_claims has invalid format")
	}

	// Look for login_id in extra claims
	loginIDValue, ok := extraClaims["login_id"]
	if !ok {
		return "", fmt.Errorf("login_id not found in token claims")
	}

	loginIDStr, ok := loginIDValue.(string)
	if !ok || loginIDStr == "" {
		return "", fmt.Errorf("login_id is not a valid string")
	}

	return loginIDStr, nil
}

// GetTokenGenerator returns the token generator for the given token name
func (js *DefaultJwtService) GetTokenGenerator(tokenName string) TokenGenerator {
	tokenGenerator, ok := js.TokenGenerators[tokenName]
	if !ok {
		return js.DefaultTokenGenerator
	}
	return tokenGenerator
}

// SetCookie sets a cookie using the cookie setter for the given cookie name
func (js *DefaultJwtService) SetCookie(w http.ResponseWriter, cookieName string, tokenValue string, expire time.Time) error {
	cookieSetter, ok := js.CookieSetters[cookieName]
	if !ok {
		cookieSetter = js.DefaultCookieSetter
	}
	return cookieSetter.SetCookie(w, cookieName, tokenValue, expire)
}

// ClearCookie clears a cookie using the cookie setter for the given cookie name
func (js *DefaultJwtService) ClearCookie(w http.ResponseWriter, cookieName string) error {
	cookieSetter, ok := js.CookieSetters[cookieName]
	if !ok {
		cookieSetter = js.DefaultCookieSetter
	}
	return cookieSetter.ClearCookie(w, cookieName)
}

// GetCookieSetter returns the cookie setter for the given cookie name
// If no specific cookie setter is found, returns the default cookie setter
func (js *DefaultJwtService) GetCookieSetter(cookieName string) CookieSetter {
	cookieSetter, ok := js.CookieSetters[cookieName]
	if !ok {
		return js.DefaultCookieSetter
	}
	return cookieSetter
}
