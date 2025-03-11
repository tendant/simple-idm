package login

import (
	"errors"

	"github.com/SuNNjek/identity"
)

// Hasher implements password hashing using the identity package
type Pbkdf2Hasher struct{}

// Hash generates a hashed password using the identity package
func (h *Pbkdf2Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Generate a salt
	salt, err := identity.GenerateSalt(identity.DefaultSaltLength)
	if err != nil {
		return "", err
	}

	// Hash the password using identity's hashing function
	hashedBytes := identity.HashPasswordV3(
		[]byte(password),
		salt,
		identity.DefaultHashAlgorithm,
		identity.DefaultIterations,
		identity.DefaultNumBytes,
	)

	return string(hashedBytes), nil
}

// Verify checks if a given password matches the stored hash
func (h *Pbkdf2Hasher) Verify(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, errors.New("password and hashed password cannot be empty")
	}

	// Verify password using identity's Verify function
	verified := identity.Verify([]byte(hashedPassword), []byte(password))
	if !verified {
		return false, nil
	}

	return true, nil
}
