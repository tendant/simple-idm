package login

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Hasher implements PasswordHasher using Argon2id
type Argon2Hasher struct {
	// Argon2 parameters
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// NewArgon2Hasher creates a new Argon2Hasher with default parameters
func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{
		memory:      64 * 1024, // 64MB
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
}

// Hash implements PasswordHasher.Hash
func (h *Argon2Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Generate a random salt
	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash the password using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.iterations,
		h.memory,
		h.parallelism,
		h.keyLength,
	)

	// Base64 encode the salt and hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.memory,
		h.iterations,
		h.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// Verify implements PasswordHasher.Verify
func (h *Argon2Hasher) Verify(password, encodedHash string) (bool, error) {
	if password == "" || encodedHash == "" {
		return false, errors.New("password and hash cannot be empty")
	}

	// Extract the parameters, salt, and hash from the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("incompatible hash algorithm")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, errors.New("invalid hash format")
	}
	if version != 19 {
		return false, errors.New("incompatible argon2id version")
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, errors.New("invalid hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}

	// Compute the hash of the provided password using the same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(decodedHash)),
	)

	// Compare the computed hash with the decoded hash
	return subtle.ConstantTimeCompare(decodedHash, computedHash) == 1, nil
}

// Version implements PasswordHasher.Version
func (h *Argon2Hasher) Version() PasswordVersion {
	return PasswordV3
}

// Argon2HasherFactory is a factory for creating Argon2 password hashers
type Argon2HasherFactory struct {
	hasherMap map[PasswordVersion]PasswordHasher
}

// NewArgon2HasherFactory creates a new Argon2HasherFactory
func NewArgon2HasherFactory() *Argon2HasherFactory {
	factory := &Argon2HasherFactory{
		hasherMap: make(map[PasswordVersion]PasswordHasher),
	}
	
	// Register hashers
	factory.hasherMap[PasswordV1] = &BcryptV1Hasher{}
	factory.hasherMap[PasswordV2] = &BcryptV2Hasher{}
	factory.hasherMap[PasswordV3] = NewArgon2Hasher()
	
	return factory
}

// GetHasher implements PasswordHasherFactory.GetHasher
func (f *Argon2HasherFactory) GetHasher(version PasswordVersion) (PasswordHasher, error) {
	hasher, ok := f.hasherMap[version]
	if !ok {
		return nil, fmt.Errorf("unsupported password version: %d", version)
	}
	return hasher, nil
}

// GetCurrentHasher implements PasswordHasherFactory.GetCurrentHasher
func (f *Argon2HasherFactory) GetCurrentHasher() PasswordHasher {
	// Default to V3 (Argon2)
	return f.hasherMap[PasswordV3]
}
