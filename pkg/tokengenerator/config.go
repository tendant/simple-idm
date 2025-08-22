package tokengenerator

import (
	"log/slog"
	"time"
)

// TokenServiceConfig holds configuration for token expiry durations
type TokenServiceConfig struct {
	AccessTokenExpiry        time.Duration
	RefreshTokenExpiry       time.Duration
	MobileRefreshTokenExpiry time.Duration
	TempTokenExpiry          time.Duration
	LogoutTokenExpiry        time.Duration
}

// TokenServiceStringConfig holds string-based configuration for token expiry durations
type TokenServiceStringConfig struct {
	AccessTokenExpiry        string
	RefreshTokenExpiry       string
	MobileRefreshTokenExpiry string
	TempTokenExpiry          string
	LogoutTokenExpiry        string
}

// NewDefaultTokenServiceWithConfig creates a new token service with custom expiry configuration
func NewDefaultTokenServiceWithConfig(accessTokenGenerator, refreshTokenGenerator, tempTokenGenerator, logoutTokenGenerator TokenGenerator, secret string, config *TokenServiceConfig) TokenService {
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
	
	// Apply custom configuration if provided
	if config != nil {
		if config.AccessTokenExpiry > 0 {
			service.accessTokenExpiry = config.AccessTokenExpiry
		}
		if config.RefreshTokenExpiry > 0 {
			service.refreshTokenExpiry = config.RefreshTokenExpiry
		}
		if config.MobileRefreshTokenExpiry > 0 {
			service.mobileRefreshTokenExpiry = config.MobileRefreshTokenExpiry
		}
		if config.TempTokenExpiry > 0 {
			service.tempTokenExpiry = config.TempTokenExpiry
		}
		if config.LogoutTokenExpiry != 0 { // Allow negative values
			service.logoutTokenExpiry = config.LogoutTokenExpiry
		}
	}
	
	return service
}

// NewDefaultTokenServiceWithStringConfig creates a new token service with string-based expiry configuration
func NewDefaultTokenServiceWithStringConfig(accessTokenGenerator, refreshTokenGenerator, tempTokenGenerator, logoutTokenGenerator TokenGenerator, secret string, stringConfig *TokenServiceStringConfig) TokenService {
	config := &TokenServiceConfig{
		AccessTokenExpiry:        DefaultAccessTokenExpiry,
		RefreshTokenExpiry:       DefaultRefreshTokenExpiry,
		MobileRefreshTokenExpiry: DefaultMobileRefreshTokenExpiry,
		TempTokenExpiry:          DefaultTempTokenExpiry,
		LogoutTokenExpiry:        DefaultLogoutTokenExpiry,
	}
	
	// Parse string durations if provided
	if stringConfig != nil {
		if d, err := time.ParseDuration(stringConfig.AccessTokenExpiry); err == nil {
			config.AccessTokenExpiry = d
		} else if stringConfig.AccessTokenExpiry != "" {
			slog.Error("Failed to parse access token expiry", "err", err, "value", stringConfig.AccessTokenExpiry)
		}
		
		if d, err := time.ParseDuration(stringConfig.RefreshTokenExpiry); err == nil {
			config.RefreshTokenExpiry = d
		} else if stringConfig.RefreshTokenExpiry != "" {
			slog.Error("Failed to parse refresh token expiry", "err", err, "value", stringConfig.RefreshTokenExpiry)
		}
		
		if d, err := time.ParseDuration(stringConfig.MobileRefreshTokenExpiry); err == nil {
			config.MobileRefreshTokenExpiry = d
		} else if stringConfig.MobileRefreshTokenExpiry != "" {
			slog.Error("Failed to parse mobile refresh token expiry", "err", err, "value", stringConfig.MobileRefreshTokenExpiry)
		}
		
		if d, err := time.ParseDuration(stringConfig.TempTokenExpiry); err == nil {
			config.TempTokenExpiry = d
		} else if stringConfig.TempTokenExpiry != "" {
			slog.Error("Failed to parse temp token expiry", "err", err, "value", stringConfig.TempTokenExpiry)
		}
		
		if d, err := time.ParseDuration(stringConfig.LogoutTokenExpiry); err == nil {
			config.LogoutTokenExpiry = d
		} else if stringConfig.LogoutTokenExpiry != "" {
			slog.Error("Failed to parse logout token expiry", "err", err, "value", stringConfig.LogoutTokenExpiry)
		}
		
		slog.Info("Token expiry configuration",
			"accessTokenExpiry", config.AccessTokenExpiry,
			"refreshTokenExpiry", config.RefreshTokenExpiry,
			"mobileRefreshTokenExpiry", config.MobileRefreshTokenExpiry,
			"tempTokenExpiry", config.TempTokenExpiry,
			"logoutTokenExpiry", config.LogoutTokenExpiry)
	}
	
	return NewDefaultTokenServiceWithConfig(accessTokenGenerator, refreshTokenGenerator, tempTokenGenerator, logoutTokenGenerator, secret, config)
}