package token

import (
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Default token expiration times
const (
	DefaultAccessTokenExpiry  = 1 * time.Minute
	DefaultRefreshTokenExpiry = 15 * time.Minute
	DefaultTempTokenExpiry    = 5 * time.Minute
)

// IdmToken represents a token with its expiry time
type IdmToken struct {
	Token  string
	Expiry time.Time
}

// Claims struct for JWT claims
type Claims struct {
	CustomClaims interface{} `json:"custom_claims,inline"`
	jwt.RegisteredClaims
}

// TokenService defines the interface for token operations
type TokenService interface {
	// CreateToken creates a new token for a user
	CreateToken(claimData interface{}) (IdmToken, error)
}

// BaseTokenConfig provides common configuration for token services
type BaseTokenConfig struct {
	Secret   string
	Issuer   string
	Subject  string
	Expiry   time.Duration
	Audience []string
}

// NewBaseTokenConfig creates a new BaseTokenConfig with the given parameters
func NewBaseTokenConfig(secret, issuer, subject string, expiry time.Duration, audience []string) BaseTokenConfig {
	return BaseTokenConfig{
		Secret:   secret,
		Issuer:   issuer,
		Subject:  subject,
		Expiry:   expiry,
		Audience: audience,
	}
}

// AccessTokenService implements TokenService for access tokens
type AccessTokenService struct {
	Config BaseTokenConfig
}

// NewAccessTokenService creates a new AccessTokenService
func NewAccessTokenService(secret string) *AccessTokenService {
	config := NewBaseTokenConfig(
		secret,
		"simple-idm",
		"simple-idm",
		DefaultAccessTokenExpiry,
		[]string{"public"},
	)
	return &AccessTokenService{Config: config}
}

// CreateToken implements TokenService for access tokens
func (s *AccessTokenService) CreateToken(claimData interface{}) (IdmToken, error) {
	claims := Claims{
		CustomClaims: claimData,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(s.Config.Expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-5 * time.Minute)),
			Issuer:    s.Config.Issuer,
			Subject:   s.Config.Subject,
			ID:        uuid.New().String(),
			Audience:  s.Config.Audience,
		},
	}

	tokenStr, err := CreateTokenStr(s.Config.Secret, claims)
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		return IdmToken{}, err
	}

	return IdmToken{
		Token:  tokenStr,
		Expiry: claims.ExpiresAt.Time,
	}, nil
}

// RefreshTokenService implements TokenService for refresh tokens
type RefreshTokenService struct {
	Config BaseTokenConfig
}

// NewRefreshTokenService creates a new RefreshTokenService
func NewRefreshTokenService(secret string) *RefreshTokenService {
	config := NewBaseTokenConfig(
		secret,
		"simple-idm",
		"simple-idm",
		DefaultRefreshTokenExpiry,
		[]string{"public"},
	)
	return &RefreshTokenService{Config: config}
}

// CreateToken implements TokenService for refresh tokens
func (s *RefreshTokenService) CreateToken(claimData interface{}) (IdmToken, error) {
	claims := Claims{
		CustomClaims: claimData,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(s.Config.Expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-5 * time.Minute)),
			Issuer:    s.Config.Issuer,
			Subject:   s.Config.Subject,
			ID:        uuid.New().String(),
			Audience:  s.Config.Audience,
		},
	}

	tokenStr, err := CreateTokenStr(s.Config.Secret, claims)
	if err != nil {
		slog.Error("Failed to create refresh token", "err", err)
		return IdmToken{}, err
	}

	return IdmToken{
		Token:  tokenStr,
		Expiry: claims.ExpiresAt.Time,
	}, nil
}

// Ensure implementations satisfy the interface
var _ TokenService = (*AccessTokenService)(nil)
var _ TokenService = (*RefreshTokenService)(nil)
