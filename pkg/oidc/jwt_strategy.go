package oidc

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateJWT creates a JWT token with the given claims
func GenerateJWT(privateKey *rsa.PrivateKey, subject string, audience string, claims map[string]interface{}) (string, error) {
	// Create the JWT claims
	jwtClaims := jwt.MapClaims{
		"iss": "https://simple-idm.example.com",
		"sub": subject,
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	// Add custom claims
	for k, v := range claims {
		jwtClaims[k] = v
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ConvertToJWT converts an opaque token to a JWT token
func ConvertToJWT(privateKey *rsa.PrivateKey, accessToken string, clientID string, userID string, scope string, extraClaims map[string]interface{}) (string, error) {
	// Create claims for the JWT
	claims := map[string]interface{}{
		"scope": scope,
		"token": accessToken, // Include the original token as a claim
	}

	// Add any extra claims
	for k, v := range extraClaims {
		claims[k] = v
	}

	// Generate the JWT
	return GenerateJWT(privateKey, userID, clientID, claims)
}
