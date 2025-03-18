package token

import (
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
	CreateToken(claimData interface{}) (Claims, error)
}

// BaseTokenConfig provides common configuration for token services
type BaseTokenConfig struct {
	Issuer   string
	Subject  string
	Expiry   time.Duration
	Audience []string
}

// NewBaseTokenConfig creates a new BaseTokenConfig with the given parameters
func NewBaseTokenConfig(issuer, subject string, expiry time.Duration, audience []string) BaseTokenConfig {
	return BaseTokenConfig{
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
func NewAccessTokenService() *AccessTokenService {
	config := NewBaseTokenConfig(
		"simple-idm",
		"simple-idm",
		DefaultAccessTokenExpiry,
		[]string{"public"},
	)
	return &AccessTokenService{Config: config}
}

// CreateToken implements TokenService for access tokens
func (s *AccessTokenService) CreateToken(claimData interface{}) (Claims, error) {
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

	// We're not generating the token string here anymore, just returning the claims
	return claims, nil
}

// RefreshTokenService implements TokenService for refresh tokens
type RefreshTokenService struct {
	Config BaseTokenConfig
}

// NewRefreshTokenService creates a new RefreshTokenService
func NewRefreshTokenService() *RefreshTokenService {
	config := NewBaseTokenConfig(
		"simple-idm",
		"simple-idm",
		DefaultRefreshTokenExpiry,
		[]string{"public"},
	)
	return &RefreshTokenService{Config: config}
}

// CreateToken implements TokenService for refresh tokens
func (s *RefreshTokenService) CreateToken(claimData interface{}) (Claims, error) {
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

	// We're not generating the token string here anymore, just returning the claims
	return claims, nil
}

// Ensure implementations satisfy the interface
var _ TokenService = (*AccessTokenService)(nil)
var _ TokenService = (*RefreshTokenService)(nil)
