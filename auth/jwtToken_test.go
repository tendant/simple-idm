package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewJwtServiceOptions(t *testing.T) {
	secret := "test-secret"
	jwtSvc := NewJwtServiceOptions(secret, WithCookieHttpOnly(true), WithCookieSecure(true))

	assert.Equal(t, secret, jwtSvc.Secret, "Secret should match")
	assert.True(t, jwtSvc.CoookieHttpOnly, "CookieHttpOnly should be true")
	assert.True(t, jwtSvc.CookieSecure, "CookieSecure should be true")
}
