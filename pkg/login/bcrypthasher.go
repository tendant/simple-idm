package login

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

// BcryptV1Hasher implements PasswordHasher using the original bcrypt implementation
type BcryptV1Hasher struct{}

// Hash implements PasswordHasher.Hash
func (h *BcryptV1Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

// Verify implements PasswordHasher.Verify
func (h *BcryptV1Hasher) Verify(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, errors.New("password and hashed password cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil // Password doesn't match, but not an error
		}
		return false, err // Some other error occurred
	}

	return true, nil
}

// BcryptV2Hasher implements PasswordHasher using bcrypt with salt and higher cost
type BcryptV2Hasher struct{}

// Hash implements PasswordHasher.Hash
func (h *BcryptV2Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Add a salt and use a higher cost
	salt := utils.GenerateRandomString(16)
	// Combine salt and password
	saltedPassword := salt + password
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost+2)
	if err != nil {
		return "", err
	}

	// Store salt and hash
	return fmt.Sprintf("%s:%s", salt, string(hashedBytes)), nil
}

// Verify implements PasswordHasher.Verify
func (h *BcryptV2Hasher) Verify(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, errors.New("password and hashed password cannot be empty")
	}

	// Version 2 format: salt:hash
	parts := strings.SplitN(hashedPassword, ":", 2)
	if len(parts) != 2 {
		return false, errors.New("invalid password hash format")
	}

	salt := parts[0]
	hash := parts[1]

	// Combine salt and password for verification
	saltedPassword := salt + password
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(saltedPassword))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil // Password doesn't match, but not an error
		}
		return false, err // Some other error occurred
	}

	return true, nil
}
