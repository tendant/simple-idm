package token

import (
	"time"
)

// Token represents a pair of access and refresh tokens
type Token struct {
	AccessToken  string
	RefreshToken string
}

// IdmToken represents a token with its expiry time
type IdmToken struct {
	Token  string
	Expiry time.Time
}

// TokenService defines the interface for token operations
type TokenService interface {
	// CreateToken creates a new token pair (access and refresh) for a user
	CreateToken(user string) (Token, error)
}
