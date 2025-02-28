package login

import (
	"errors"
)

// CheckPasswordHash is a utility function that checks if a password matches a hash
// This is provided for backward compatibility with existing code
func CheckPasswordHash(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, errors.New("password and hashed password cannot be empty")
	}

	// Use the default V1 hasher for backward compatibility
	hasher := &BcryptV1Hasher{}
	return hasher.Verify(password, hashedPassword)
}

// HashPassword is a utility function that hashes a password
// This is provided for backward compatibility with existing code
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Use the default V1 hasher for backward compatibility
	hasher := &BcryptV1Hasher{}
	return hasher.Hash(password)
}
