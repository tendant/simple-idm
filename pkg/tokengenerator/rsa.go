package tokengenerator

import (
	"crypto/rsa"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RSATokenGenerator implements the TokenGenerator interface using RSA signing
type RSATokenGenerator struct {
	privateKey *rsa.PrivateKey
	keyID      string
	issuer     string
	audience   string
}

// NewRSATokenGenerator creates a new RSA token generator
func NewRSATokenGenerator(privateKey *rsa.PrivateKey, keyID, issuer, audience string) *RSATokenGenerator {
	return &RSATokenGenerator{
		privateKey: privateKey,
		keyID:      keyID,
		issuer:     issuer,
		audience:   audience,
	}
}

// GenerateToken creates a new RSA-signed token with the given subject and claims
func (g *RSATokenGenerator) GenerateToken(subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)

	// Create base claims
	claims := jwt.MapClaims{
		"iss": g.issuer,
		"sub": subject,
		"aud": g.audience,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-5 * time.Minute).Unix(), // Not before (with 5 min tolerance)
		"jti": uuid.New().String(),
	}

	// Apply root modifications (these override base claims)
	for key, value := range rootModifications {
		claims[key] = value
	}

	// Add extra claims
	for key, value := range extraClaims {
		claims[key] = value
	}

	// Create token with RSA signing method and include key ID in header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyID

	// Sign the token
	tokenString, err := token.SignedString(g.privateKey)
	if err != nil {
		slog.Error("Failed to sign RSA JWT token", "err", err)
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// ParseToken parses and validates an RSA-signed token string
func (g *RSATokenGenerator) ParseToken(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key for verification
		return &g.privateKey.PublicKey, nil
	})

	if err != nil {
		slog.Error("Failed to parse RSA JWT token", "err", err)
		return token, err
	}

	if token.Valid {
		return token, nil
	}

	slog.Error("RSA JWT token is invalid")
	return token, fmt.Errorf("invalid token")
}

// GetKeyID returns the key ID used by this token generator
func (g *RSATokenGenerator) GetKeyID() string {
	return g.keyID
}

// GetPublicKey returns the public key for this token generator
func (g *RSATokenGenerator) GetPublicKey() *rsa.PublicKey {
	return &g.privateKey.PublicKey
}
