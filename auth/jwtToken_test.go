package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewJwtServiceOptions(t *testing.T) {
	secret := "test-secret"
	jwtSvc := NewJwtServiceOptions(secret, WithCookieHttpOnly(true), WithCookieSecure(true))

	assert.Equal(t, secret, jwtSvc.Secret, "Secret should match")
	assert.True(t, jwtSvc.CoookieHttpOnly, "CookieHttpOnly should be true")
	assert.True(t, jwtSvc.CookieSecure, "CookieSecure should be true")
}

func TestCreateAccessToken(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"role": "user"}

	token, err := jwtSvc.CreateAccessToken(claimData)
	assert.NoError(t, err, "CreateAccessToken should not return an error")
	assert.NotEmpty(t, token.Token, "AccessToken should not be empty")
	assert.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), token.Expiry, time.Second, "Token expiry should be 5 minutes from now")
}

func TestCreateRefreshToken(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"role": "user"}

	token, err := jwtSvc.CreateRefreshToken(claimData)
	assert.NoError(t, err, "CreateRefreshToken should not return an error")
	assert.NotEmpty(t, token.Token, "RefreshToken should not be empty")
	assert.WithinDuration(t, time.Now().UTC().Add(15*time.Minute), token.Expiry, time.Second, "Token expiry should be 15 minutes from now")
}

func TestValidateRefreshToken(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"role": "user"}

	// Create a valid refresh token
	token, err := jwtSvc.CreateRefreshToken(claimData)
	assert.NoError(t, err, "CreateRefreshToken should not return an error")

	// Validate the token
	claims, err := jwtSvc.ValidateRefreshToken(token.Token)
	assert.NoError(t, err, "ValidateRefreshToken should not return an error")
	assert.Equal(t, "user", claims["custom_claims"].(map[string]interface{})["role"], "Role should match")
}

func TestValidateRefreshToken2(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"role": []string{"admin", "support"}}

	// Create a valid refresh token
	token, err := jwtSvc.CreateRefreshToken(claimData)
	assert.NoError(t, err, "CreateRefreshToken should not return an error")

	// Validate the token
	claims, err := jwtSvc.ValidateRefreshToken(token.Token)
	assert.NoError(t, err, "ValidateRefreshToken should not return an error")
	assert.Equal(t, []interface{}{"admin", "support"}, claims["custom_claims"].(map[string]interface{})["role"], "Role should match")
}

func TestValidateExpiredToken(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"role": "user"}

	// Create a token with a past expiration time
	token, err := jwtSvc.CreateAccessToken(claimData)
	assert.NoError(t, err, "CreateAccessToken should not return an error")

	// Manually tamper with the token to simulate expiration
	expiredToken := token.Token[:len(token.Token)-1] + "a"

	_, err = jwtSvc.ValidateRefreshToken(expiredToken)
	assert.Error(t, err, "ValidateRefreshToken should fail for expired token")
}

func TestParseTokenStr(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"role": "admin"}

	// Create a token
	token, err := jwtSvc.CreateAccessToken(claimData)
	assert.NoError(t, err, "CreateAccessToken should not return an error")

	// Parse the token
	parsedToken, err := jwtSvc.ParseTokenStr(token.Token)
	assert.NoError(t, err, "ParseTokenStr should not return an error")

	claims := parsedToken.Claims.(jwt.MapClaims)
	assert.Equal(t, "admin", claims["custom_claims"].(map[string]interface{})["role"], "Role should match")
}

func TestCreatePasswordResetToken(t *testing.T) {
	jwtSvc := NewJwtServiceOptions("test-secret")
	claimData := map[string]interface{}{"email": "test@example.com"}

	token, err := jwtSvc.CreatePasswordResetToken(claimData)
	assert.NoError(t, err, "CreatePasswordResetToken should not return an error")
	assert.NotEmpty(t, token, "PasswordResetToken should not be empty")
}
