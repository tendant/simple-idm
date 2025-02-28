package login

// PasswordVersion represents the version of the password hashing algorithm
type PasswordVersion int

const (
	// PasswordV1 is the original bcrypt implementation
	PasswordV1 PasswordVersion = 1
	// PasswordV2 adds salt and uses a higher cost
	PasswordV2 PasswordVersion = 2
	// PasswordV3 is reserved for future implementation (Argon2)
	PasswordV3 PasswordVersion = 3
	
	// CurrentPasswordVersion is the current version used for new passwords
	CurrentPasswordVersion = PasswordV2
)

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
