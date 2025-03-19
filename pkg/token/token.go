package token

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Default token expiration times
const (
	DefaultAccessTokenExpiry   = 5 * time.Minute
	DefaultRefreshTokenExpiry  = 15 * time.Minute
	DefaultTempTokenExpiry     = 5 * time.Minute
	DefaultPasswordResetExpiry = 30 * time.Minute
	DefaultLogoutTokenExpiry   = -1 * time.Minute // Negative to make it immediately expired
)

// Claims struct for JWT claims
type Claims struct {
	ExtraClaims  interface{} `json:"extra_claims,inline"`
	CustomClaims interface{} `json:"custom_claims,inline"`
	jwt.RegisteredClaims
}

// TokenService defines the interface for token operations
type TokenService interface {
	// CreateToken creates a new token for a user
	CreateToken(claimData interface{}) (Claims, error)
	SetTokenCookie(w http.ResponseWriter, tokenStr string, expiry time.Time) error
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
		ExtraClaims:  claimData,
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

// SetTokenCookie sets a cookie with the access token
func (s *AccessTokenService) SetTokenCookie(w http.ResponseWriter, tokenStr string, expiry time.Time) error {
	tokenCookie := &http.Cookie{
		Name:     "access_token",
		Path:     "/",
		Value:    tokenStr,
		Expires:  expiry,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it's sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
	return nil
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
		ExtraClaims:  claimData,
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

// SetTokenCookie sets a cookie with the refresh token
func (s *RefreshTokenService) SetTokenCookie(w http.ResponseWriter, tokenStr string, expiry time.Time) error {
	tokenCookie := &http.Cookie{
		Name:     "refresh_token",
		Path:     "/",
		Value:    tokenStr,
		Expires:  expiry,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it's sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
	return nil
}

// PasswordResetTokenService implements TokenService for password reset tokens
type PasswordResetTokenService struct {
	Config BaseTokenConfig
}

// NewPasswordResetTokenService creates a new PasswordResetTokenService
func NewPasswordResetTokenService() *PasswordResetTokenService {
	config := NewBaseTokenConfig(
		"simple-idm",
		"simple-idm",
		DefaultPasswordResetExpiry,
		[]string{"public"},
	)
	return &PasswordResetTokenService{Config: config}
}

// CreateToken implements TokenService for password reset tokens
func (s *PasswordResetTokenService) CreateToken(claimData interface{}) (Claims, error) {
	claims := Claims{
		ExtraClaims:  claimData,
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

// SetTokenCookie sets a cookie with the password reset token
func (s *PasswordResetTokenService) SetTokenCookie(w http.ResponseWriter, tokenStr string, expiry time.Time) error {
	tokenCookie := &http.Cookie{
		Name:     "access_token",
		Path:     "/",
		Value:    tokenStr,
		Expires:  expiry,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it's sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
	return nil
}

// LogoutTokenService implements TokenService for logout tokens
type LogoutTokenService struct {
	Config BaseTokenConfig
}

// NewLogoutTokenService creates a new LogoutTokenService
func NewLogoutTokenService() *LogoutTokenService {
	config := NewBaseTokenConfig(
		"simple-idm",
		"simple-idm",
		DefaultLogoutTokenExpiry,
		[]string{"public"},
	)
	return &LogoutTokenService{Config: config}
}

// CreateToken implements TokenService for logout tokens
func (s *LogoutTokenService) CreateToken(claimData interface{}) (Claims, error) {
	claims := Claims{
		ExtraClaims:  claimData,
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

// SetTokenCookie sets a cookie with the logout token
func (s *LogoutTokenService) SetTokenCookie(w http.ResponseWriter, tokenStr string, expiry time.Time) error {

	accessCookie := &http.Cookie{
		Name:     "access_token",
		Path:     "/",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, accessCookie)

	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Path:     "/",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, refreshCookie)

	return nil
}

// TempTokenService implements TokenService for temporary tokens (e.g., 2FA)
type TempTokenService struct {
	Config BaseTokenConfig
}

// NewTempTokenService creates a new TempTokenService
func NewTempTokenService() *TempTokenService {
	config := NewBaseTokenConfig(
		"simple-idm",
		"simple-idm",
		DefaultTempTokenExpiry,
		[]string{"2fa"},
	)
	return &TempTokenService{Config: config}
}

// CreateToken implements TokenService for temporary tokens
func (s *TempTokenService) CreateToken(claimData interface{}) (Claims, error) {
	claims := Claims{
		ExtraClaims:  claimData,
		CustomClaims: claimData,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(s.Config.Expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			Issuer:    s.Config.Issuer,
			Subject:   s.Config.Subject,
			ID:        uuid.New().String(),
			Audience:  s.Config.Audience,
		},
	}

	// We're not generating the token string here anymore, just returning the claims
	return claims, nil
}

// SetTokenCookie sets a cookie with the temporary token
func (s *TempTokenService) SetTokenCookie(w http.ResponseWriter, tokenStr string, expiry time.Time) error {
	tokenCookie := &http.Cookie{
		Name:     "temp_token",
		Path:     "/",
		Value:    tokenStr,
		Expires:  expiry,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it's sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
	return nil
}

// Ensure implementations satisfy the interface
var _ TokenService = (*AccessTokenService)(nil)
var _ TokenService = (*RefreshTokenService)(nil)
var _ TokenService = (*PasswordResetTokenService)(nil)
var _ TokenService = (*LogoutTokenService)(nil)
var _ TokenService = (*TempTokenService)(nil)
