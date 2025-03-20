package tokengenerator

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenGenerator interface defines methods for token operations
type TokenGenerator interface {
	// GenerateToken generates a token with the given subject, expiry, root modifications and extra claims
	GenerateToken(subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error)

	// ParseToken parses and validates a token
	ParseToken(tokenStr string) (*jwt.Token, error)
}

// Claims struct for JWT claims
type Claims struct {
	ExtraClaims  interface{} `json:"extra_claims,omitempty"`
	CustomClaims interface{} `json:"custom_claims,omitempty"`
	jwt.RegisteredClaims
}

// JwtTokenGenerator implements the TokenGenerator interface
type JwtTokenGenerator struct {
	Secret   string
	Issuer   string
	Audience string
}

// NewJwtTokenGenerator creates a new JwtTokenGenerator
func NewJwtTokenGenerator(secret, issuer, audience string) *JwtTokenGenerator {
	return &JwtTokenGenerator{
		Secret:   secret,
		Issuer:   issuer,
		Audience: audience,
	}
}

// GenerateToken creates a new token with the given subject and claims
func (g *JwtTokenGenerator) GenerateToken(subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error) {
	claims := Claims{
		ExtraClaims:  extraClaims,
		CustomClaims: extraClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-5 * time.Minute)),
			Issuer:    g.Issuer,
			Subject:   subject,
			ID:        uuid.New().String(),
			Audience:  jwt.ClaimStrings{g.Audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signingKey := []byte(g.Secret)
	ss, err := signedString(signingKey, token)
	if err != nil {
		slog.Error("Failed sign JWT Claim string!", "err", err)
		return "", time.Time{}, err
	}
	return ss, claims.ExpiresAt.Time, nil
}

// ParseToken parses and validates a token string
func (g *JwtTokenGenerator) ParseToken(tokenStr string) (*jwt.Token, error) {
	signingKey := []byte(g.Secret)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		slog.Error("Failed parse JWT string!", "err", err)
		return token, err
	}

	// Since we don't have a LoadFromMap function or Claims struct defined,
	// we'll just return the token if it's valid
	if token.Valid {
		return token, nil
	}

	slog.Error("Failed parse token claims!", "err", "token invalid")
	return token, fmt.Errorf("failed_parse_token_claims")
}
