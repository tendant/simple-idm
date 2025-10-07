package emailverification

import "errors"

var (
	// ErrTokenNotFound is returned when a verification token is not found
	ErrTokenNotFound = errors.New("verification token not found")

	// ErrTokenExpired is returned when a verification token has expired
	ErrTokenExpired = errors.New("verification token has expired")

	// ErrTokenAlreadyUsed is returned when a verification token has already been used
	ErrTokenAlreadyUsed = errors.New("verification token has already been used")

	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")

	// ErrEmailAlreadyVerified is returned when trying to verify an already verified email
	ErrEmailAlreadyVerified = errors.New("email already verified")

	// ErrRateLimitExceeded is returned when the rate limit for sending verification emails is exceeded
	ErrRateLimitExceeded = errors.New("too many verification emails sent, please try again later")

	// ErrInvalidToken is returned when the token format is invalid
	ErrInvalidToken = errors.New("invalid verification token")
)

// These are re-exported from service.go for backward compatibility
var (
	ErrAlreadyVerified = ErrEmailAlreadyVerified
)
