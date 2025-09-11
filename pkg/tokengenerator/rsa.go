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

	claims := Claims{
		ExtraClaims: extraClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-5 * time.Minute)),
			Issuer:    g.issuer,
			Subject:   subject,
			ID:        uuid.New().String(),
			Audience:  jwt.ClaimStrings{g.audience},
		},
	}
	// Apply root modifications to the registered claims
	if rootModifications != nil {
		if iss, ok := rootModifications["iss"].(string); ok {
			claims.RegisteredClaims.Issuer = iss
		}
		if sub, ok := rootModifications["sub"].(string); ok {
			claims.RegisteredClaims.Subject = sub
		}
		if aud, ok := rootModifications["aud"].([]string); ok {
			claims.RegisteredClaims.Audience = jwt.ClaimStrings(aud)
		}
		if jti, ok := rootModifications["jti"].(string); ok {
			claims.RegisteredClaims.ID = jti
		}
		if email, ok := rootModifications["email"].(string); ok {
			claims.Email = email
		}
		if username, ok := rootModifications["username"].(string); ok {
			claims.Username = username
		}
		if emailVerified, ok := rootModifications["email_verified"].(bool); ok {
			claims.EmailVerified = emailVerified
		}
		if phone, ok := rootModifications["phone"].(string); ok {
			claims.PhoneNumber = phone
		}
		if phoneVerified, ok := rootModifications["phone_number_verified"].(bool); ok {
			claims.PhoneNumberVerified = phoneVerified
		}
		if groups, ok := rootModifications["groups"].([]string); ok {
			claims.Groups = groups
		}
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

	return tokenString, claims.ExpiresAt.Time, nil
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

type TempRSATokenGenerator struct {
	privateKey *rsa.PrivateKey
	keyID      string
	issuer     string
	audience   string
}

// NewRSATokenGenerator creates a new RSA token generator
func NewTempRSATokenGenerator(privateKey *rsa.PrivateKey, keyID, issuer, audience string) *TempRSATokenGenerator {
	return &TempRSATokenGenerator{
		privateKey: privateKey,
		keyID:      keyID,
		issuer:     issuer,
		audience:   audience,
	}
}

// GenerateToken creates a new RSA-signed token with the given subject and claims
func (g *TempRSATokenGenerator) GenerateToken(subject string, expiry time.Duration, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (string, time.Time, error) {
	// Add temp token specific metadata to extra claims if not already present
	if extraClaims == nil {
		slog.Error("extra claims not found", "err", "extra claims not found")
		return "", time.Time{}, fmt.Errorf("extra claims not found")
	}

	// Add token type and creation timestamp if not already set
	if _, exists := extraClaims["login_id"]; !exists {
		slog.Error("login_id not found in claims", "err", "login_id not found in claims")
		return "", time.Time{}, fmt.Errorf("login_id not found in claims")
	}

	tempClaims := map[string]interface{}{
		"login_id": extraClaims["login_id"],
	}
	if _, exists := extraClaims["associate_users"]; exists {
		tempClaims["associate_users"] = extraClaims["associate_users"]
	}
	if _, exists := extraClaims["2fa_verified"]; exists {
		tempClaims["2fa_verified"] = extraClaims["2fa_verified"]
	}

	// Create claims with shorter tolerance for time skew
	claims := Claims{
		ExtraClaims: tempClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC().Add(-1 * time.Minute)), // Shorter tolerance for temp tokens
			Issuer:    g.issuer,
			Subject:   subject,
			ID:        uuid.New().String(),
			Audience:  jwt.ClaimStrings{g.audience},
		},
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

	return tokenString, claims.ExpiresAt.Time, nil
}

// ParseToken parses and validates an RSA-signed token string
func (g *TempRSATokenGenerator) ParseToken(tokenStr string) (*jwt.Token, error) {
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
func (g *TempRSATokenGenerator) GetKeyID() string {
	return g.keyID
}

// GetPublicKey returns the public key for this token generator
func (g *TempRSATokenGenerator) GetPublicKey() *rsa.PublicKey {
	return &g.privateKey.PublicKey
}
