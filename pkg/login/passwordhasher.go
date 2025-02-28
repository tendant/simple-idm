package login

import (
	"errors"
	"fmt"
)

// PasswordVersion represents the version of the password hashing algorithm
type PasswordVersion int

// PasswordHasher defines the interface for password hashing implementations
type PasswordHasher interface {
	// Hash hashes a password
	Hash(password string) (string, error)

	// Verify checks if the provided password matches the stored hash
	Verify(password, hashedPassword string) (bool, error)
}

// PasswordHasherFactory creates password hashers based on version
type PasswordHasherFactory interface {
	// GetHasher returns a password hasher for the specified version
	GetHasher(version PasswordVersion) (PasswordHasher, error)
}

// DefaultPasswordHasherFactory is the default implementation of PasswordHasherFactory
type DefaultPasswordHasherFactory struct {
	currentVersion PasswordVersion
}

// NewDefaultPasswordHasherFactory creates a new DefaultPasswordHasherFactory
func NewDefaultPasswordHasherFactory(currentVersion PasswordVersion) *DefaultPasswordHasherFactory {
	return &DefaultPasswordHasherFactory{
		currentVersion: currentVersion,
	}
}

const (
	// PasswordV1 is the original bcrypt implementation
	PasswordV1 PasswordVersion = 1
	// PasswordV2 is reserved for future implementation
	PasswordV2 PasswordVersion = 2
	// PasswordV3 is reserved for future implementation
	PasswordV3 PasswordVersion = 3

	// CurrentPasswordVersion is the current version used for new passwords
	CurrentPasswordVersion = PasswordV1
)

// GetHasher implements PasswordHasherFactory.GetHasher
func (f *DefaultPasswordHasherFactory) GetHasher(version PasswordVersion) (PasswordHasher, error) {
	switch version {
	case PasswordV1:
		return &BcryptV1Hasher{}, nil
	case PasswordV2:
		return nil, errors.New("password version 2 not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported password version: %d", version)
	}
}
