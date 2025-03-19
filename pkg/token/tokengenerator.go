package token

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// CustomClaims merges extra claims and allows modifying root claims dynamically.
type CustomClaims struct {
	jwt.RegisteredClaims                        // Standard JWT claims
	CustomIssuer         string                 `json:"custom_iss,omitempty"` // Example of a modified root claim
	CustomAudience       string                 `json:"custom_aud,omitempty"` // Another example
	ExtraClaims          map[string]interface{} `json:"extra_claims"`
	CustomClaims         map[string]interface{} `json:"custom_claims"`
}

// TokenGenerator defines the JWT creation and parsing interface.
type TokenGenerator interface {
	// ParseToken parses and validates a token string
	ParseToken(tokenString string) (*jwt.Token, error)

	// GenerateToken creates a token with the given parameters
	GenerateToken(subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error)

	// SetCookie sets a token as a cookie in the HTTP response
	SetCookie(w http.ResponseWriter, cookieName string, token string, expiry time.Time) error
}

// TokenGeneratorConfig holds configuration for JWT token generation and signing.
type TokenGeneratorConfig struct {
	Secret          string
	SigningMethod   jwt.SigningMethod
	DefaultIssuer   string
	DefaultAudience string
	CookieHttpOnly  bool
	CookieSecure    bool
	CookiePath      string
	CookieDomain    string
	CookieSameSite  http.SameSite
}

// JWTService provides the implementation of the TokenGenerator.
type JWTService struct {
	config TokenGeneratorConfig
}

// NewTokenGenerator creates a new TokenGenerator with the given configuration.
func NewTokenGenerator(config TokenGeneratorConfig) TokenGenerator {
	// Set default signing method if not specified
	if config.SigningMethod == nil {
		config.SigningMethod = jwt.SigningMethodHS256
	}

	// Set default issuer if not specified
	if config.DefaultIssuer == "" {
		config.DefaultIssuer = APPLICATION_NAME
	}

	// Set default audience if not specified
	if config.DefaultAudience == "" {
		config.DefaultAudience = APPLICATION_NAME
	}

	// Set secure defaults for cookies
	if config.CookiePath == "" {
		config.CookiePath = "/"
	}

	// Default to secure cookies in production
	if !config.CookieHttpOnly {
		config.CookieHttpOnly = true
	}

	// Default to SameSite=Lax if not specified
	if config.CookieSameSite == 0 {
		config.CookieSameSite = http.SameSiteLaxMode
	}

	return &JWTService{
		config: config,
	}
}

// GenerateToken creates a JWT, modifying root claims and merging extra claims.
func (s *JWTService) GenerateToken(subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error) {
	// Initialize custom claims with registered claims
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-5 * time.Minute)),
			Issuer:    s.config.DefaultIssuer,
			Subject:   subject,
			ID:        uuid.New().String(),
			Audience:  jwt.ClaimStrings{s.config.DefaultAudience},
		},
		ExtraClaims:  extraClaims,
		CustomClaims: extraClaims,
	}

	tokenExpiry := claims.ExpiresAt.Time

	ss, err := CreateTokenStr(s.config.Secret, claims)
	if err != nil {
		slog.Error("Failed sign JWT Claim string!", "err", err)
		return "", time.Time{}, err
	}
	return ss, tokenExpiry, nil
}

// ParseToken verifies and extracts claims from a token.
func (s *JWTService) ParseToken(tokenString string) (*jwt.Token, error) {
	return ParseTokenStr(s.config.Secret, tokenString)
}

// SetCookie sets a token as a cookie in the HTTP response.
func (s *JWTService) SetCookie(w http.ResponseWriter, name string, token string, expiry time.Time) error {
	cookie := &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     s.config.CookiePath,
		Domain:   s.config.CookieDomain,
		Expires:  expiry,
		MaxAge:   int(time.Until(expiry).Seconds()),
		Secure:   s.config.CookieSecure,
		HttpOnly: s.config.CookieHttpOnly,
		SameSite: s.config.CookieSameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}

// GenerateAndSetCookie combines token generation and cookie setting in one operation
// This method is kept for backward compatibility
func (s *JWTService) GenerateAndSetCookie(w http.ResponseWriter, cookieName string, subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, error) {
	token, tokenExpiry, err := s.GenerateToken(subject, expiry, rootModifications, extraClaims)
	if err != nil {
		return "", err
	}

	err = s.SetCookie(w, cookieName, token, tokenExpiry)
	if err != nil {
		return "", err
	}

	return token, nil
}
