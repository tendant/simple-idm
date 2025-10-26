package tokengenerator

import (
	"crypto/rsa"
	"fmt"
	"log/slog"
	"time"
)

// Option configures a DefaultTokenService
type Option func(*DefaultTokenService)

// parseDurationValue parses either a string or time.Duration into time.Duration
func parseDurationValue(v interface{}) (time.Duration, error) {
	switch val := v.(type) {
	case time.Duration:
		return val, nil
	case string:
		if val == "" {
			return 0, nil
		}
		return time.ParseDuration(val)
	default:
		return 0, fmt.Errorf("invalid duration type: %T", v)
	}
}

// WithAccessTokenExpiry sets the access token expiry duration
// Accepts either time.Duration or string (e.g., "1h", "30m")
func WithAccessTokenExpiry(expiry interface{}) Option {
	return func(s *DefaultTokenService) {
		if d, err := parseDurationValue(expiry); err == nil && d > 0 {
			s.accessTokenExpiry = d
		} else if err != nil {
			slog.Error("Failed to parse access token expiry", "err", err, "value", expiry)
		}
	}
}

// WithRefreshTokenExpiry sets the refresh token expiry duration
// Accepts either time.Duration or string (e.g., "24h", "7d")
func WithRefreshTokenExpiry(expiry interface{}) Option {
	return func(s *DefaultTokenService) {
		if d, err := parseDurationValue(expiry); err == nil && d > 0 {
			s.refreshTokenExpiry = d
		} else if err != nil {
			slog.Error("Failed to parse refresh token expiry", "err", err, "value", expiry)
		}
	}
}

// WithMobileRefreshTokenExpiry sets the mobile refresh token expiry duration
// Accepts either time.Duration or string (e.g., "90d", "2160h")
func WithMobileRefreshTokenExpiry(expiry interface{}) Option {
	return func(s *DefaultTokenService) {
		if d, err := parseDurationValue(expiry); err == nil && d > 0 {
			s.mobileRefreshTokenExpiry = d
		} else if err != nil {
			slog.Error("Failed to parse mobile refresh token expiry", "err", err, "value", expiry)
		}
	}
}

// WithTempTokenExpiry sets the temporary token expiry duration
// Accepts either time.Duration or string (e.g., "10m", "600s")
func WithTempTokenExpiry(expiry interface{}) Option {
	return func(s *DefaultTokenService) {
		if d, err := parseDurationValue(expiry); err == nil && d > 0 {
			s.tempTokenExpiry = d
		} else if err != nil {
			slog.Error("Failed to parse temp token expiry", "err", err, "value", expiry)
		}
	}
}

// WithLogoutTokenExpiry sets the logout token expiry duration
// Accepts either time.Duration or string (e.g., "-1s", "0s")
func WithLogoutTokenExpiry(expiry interface{}) Option {
	return func(s *DefaultTokenService) {
		if d, err := parseDurationValue(expiry); err == nil {
			s.logoutTokenExpiry = d // Allow zero or negative values for logout token
		} else if err != nil {
			slog.Error("Failed to parse logout token expiry", "err", err, "value", expiry)
		}
	}
}

func WithPrivateKey(privateKey *rsa.PrivateKey) Option {
	return func(s *DefaultTokenService) {
		s.privateKey = privateKey
	}
}

func WithSecret(secret string) Option {
	return func(s *DefaultTokenService) {
		s.Secret = secret
	}
}

// NewDefaultTokenServiceWithOptions creates a new token service with options
func NewDefaultTokenServiceWithOptions(accessTokenGenerator, refreshTokenGenerator, tempTokenGenerator, logoutTokenGenerator TokenGenerator, secret string, opts ...Option) TokenService {
	service := &DefaultTokenService{
		accessTokenGenerator:     accessTokenGenerator,
		refreshTokenGenerator:    refreshTokenGenerator,
		tempTokenGenerator:       tempTokenGenerator,
		logoutTokenGenerator:     logoutTokenGenerator,
		Secret:                   secret,
		accessTokenExpiry:        DefaultAccessTokenExpiry,
		refreshTokenExpiry:       DefaultRefreshTokenExpiry,
		mobileRefreshTokenExpiry: DefaultMobileRefreshTokenExpiry,
		tempTokenExpiry:          DefaultTempTokenExpiry,
		logoutTokenExpiry:        DefaultLogoutTokenExpiry,
	}

	// Apply options
	for _, opt := range opts {
		opt(service)
	}

	slog.Info("Token service configured",
		"accessTokenExpiry", service.accessTokenExpiry,
		"refreshTokenExpiry", service.refreshTokenExpiry,
		"mobileRefreshTokenExpiry", service.mobileRefreshTokenExpiry,
		"tempTokenExpiry", service.tempTokenExpiry,
		"logoutTokenExpiry", service.logoutTokenExpiry)

	return service
}

// 2025-09-03: new constructor that support either RSA or HMAC
func NewTokenServiceWithOptions(accessTokenGenerator, refreshTokenGenerator, tempTokenGenerator, logoutTokenGenerator TokenGenerator, opts ...Option) TokenService {
	service := &DefaultTokenService{
		accessTokenGenerator:     accessTokenGenerator,
		refreshTokenGenerator:    refreshTokenGenerator,
		tempTokenGenerator:       tempTokenGenerator,
		logoutTokenGenerator:     logoutTokenGenerator,
		accessTokenExpiry:        DefaultAccessTokenExpiry,
		refreshTokenExpiry:       DefaultRefreshTokenExpiry,
		mobileRefreshTokenExpiry: DefaultMobileRefreshTokenExpiry,
		tempTokenExpiry:          DefaultTempTokenExpiry,
		logoutTokenExpiry:        DefaultLogoutTokenExpiry,
	}

	// Apply options
	for _, opt := range opts {
		opt(service)
	}

	slog.Info("Token service configured",
		"accessTokenExpiry", service.accessTokenExpiry,
		"refreshTokenExpiry", service.refreshTokenExpiry,
		"mobileRefreshTokenExpiry", service.mobileRefreshTokenExpiry,
		"tempTokenExpiry", service.tempTokenExpiry,
		"logoutTokenExpiry", service.logoutTokenExpiry,
		"using RSA", service.privateKey != nil,
		"using secret", service.Secret != "")
	return service
}

// WithTempTokenGenerator overrides the temporary token generator
// Use this when you need different behavior for temp tokens (e.g., claim filtering)
func WithTempTokenGenerator(generator TokenGenerator) Option {
	return func(s *DefaultTokenService) {
		s.tempTokenGenerator = generator
	}
}

// NewTokenServiceFromGenerator creates a TokenService from a single generator
// The same generator is used for access, refresh, temp, and logout tokens
// Use WithTempTokenGenerator() option to override temp token behavior if needed
//
// Example:
//
//	tokenService := tokengenerator.NewTokenServiceFromGenerator(
//	    tokengenerator.NewRSATokenGenerator(privateKey, keyID, issuer, audience),
//	    tokengenerator.WithAccessTokenExpiry("15m"),
//	    tokengenerator.WithTempTokenGenerator(customTempGenerator),
//	)
func NewTokenServiceFromGenerator(generator TokenGenerator, opts ...Option) TokenService {
	service := &DefaultTokenService{
		accessTokenGenerator:     generator,
		refreshTokenGenerator:    generator,
		tempTokenGenerator:       generator,
		logoutTokenGenerator:     generator,
		accessTokenExpiry:        DefaultAccessTokenExpiry,
		refreshTokenExpiry:       DefaultRefreshTokenExpiry,
		mobileRefreshTokenExpiry: DefaultMobileRefreshTokenExpiry,
		tempTokenExpiry:          DefaultTempTokenExpiry,
		logoutTokenExpiry:        DefaultLogoutTokenExpiry,
	}

	// Extract private key from RSA generator if available
	if rsaGen, ok := generator.(*RSATokenGenerator); ok {
		service.privateKey = rsaGen.privateKey
	}

	// Apply options
	for _, opt := range opts {
		opt(service)
	}

	slog.Info("Token service configured (from single generator)",
		"accessTokenExpiry", service.accessTokenExpiry,
		"refreshTokenExpiry", service.refreshTokenExpiry,
		"mobileRefreshTokenExpiry", service.mobileRefreshTokenExpiry,
		"tempTokenExpiry", service.tempTokenExpiry,
		"logoutTokenExpiry", service.logoutTokenExpiry,
		"using RSA", service.privateKey != nil,
		"using secret", service.Secret != "")

	return service
}
