package login

import (
	"fmt"
	"time"
)

// Config holds configuration for the LoginService
// Use this struct for environment-based configuration or programmatic setup
type Config struct {
	// Account Lockout Settings
	MaxFailedAttempts int           `json:"max_failed_attempts"` // Maximum failed login attempts before lockout (default: 5)
	LockoutDuration   time.Duration `json:"lockout_duration"`    // Duration to lock account after max failures (default: 30m)

	// Magic Link Settings
	MagicLinkTokenExpiration time.Duration `json:"magic_link_token_expiration"` // Magic link token validity (default: 15m)

	// Password Policy (optional - uses PasswordManager defaults if not set)
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`
}

// PasswordPolicy defines password complexity requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`         // Minimum password length (default: 8)
	RequireUppercase bool `json:"require_uppercase"`  // Require at least one uppercase letter
	RequireLowercase bool `json:"require_lowercase"`  // Require at least one lowercase letter
	RequireNumber    bool `json:"require_number"`     // Require at least one number
	RequireSpecial   bool `json:"require_special"`    // Require at least one special character
	MaxLength        int  `json:"max_length"`         // Maximum password length (default: 128)
	PreventReuse     int  `json:"prevent_reuse"`      // Number of previous passwords to prevent reuse (default: 0)
	ExpirationDays   int  `json:"expiration_days"`    // Days until password expires (0 = never, default: 0)
	CheckDictionary  bool `json:"check_dictionary"`   // Check against common password dictionary
	MinEntropyBits   int  `json:"min_entropy_bits"`   // Minimum password entropy in bits (0 = no check)
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxFailedAttempts:        5,
		LockoutDuration:          30 * time.Minute,
		MagicLinkTokenExpiration: 15 * time.Minute,
		PasswordPolicy:           DefaultPasswordPolicy(),
	}
}

// DefaultPasswordPolicy returns a PasswordPolicy with secure defaults
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   false, // Not required by default for better UX
		MaxLength:        128,
		PreventReuse:     0,  // No password history by default
		ExpirationDays:   0,  // Passwords don't expire by default
		CheckDictionary:  false, // Dictionary check disabled by default (requires external list)
		MinEntropyBits:   0,  // No entropy requirement by default
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.MaxFailedAttempts < 0 {
		return fmt.Errorf("max_failed_attempts must be non-negative, got %d", c.MaxFailedAttempts)
	}

	if c.LockoutDuration < 0 {
		return fmt.Errorf("lockout_duration must be non-negative, got %v", c.LockoutDuration)
	}

	if c.MagicLinkTokenExpiration <= 0 {
		return fmt.Errorf("magic_link_token_expiration must be positive, got %v", c.MagicLinkTokenExpiration)
	}

	if c.PasswordPolicy != nil {
		if err := c.PasswordPolicy.Validate(); err != nil {
			return fmt.Errorf("invalid password policy: %w", err)
		}
	}

	return nil
}

// Validate checks if the password policy is valid
func (p *PasswordPolicy) Validate() error {
	if p.MinLength < 1 {
		return fmt.Errorf("min_length must be at least 1, got %d", p.MinLength)
	}

	if p.MaxLength < p.MinLength {
		return fmt.Errorf("max_length (%d) must be >= min_length (%d)", p.MaxLength, p.MinLength)
	}

	if p.PreventReuse < 0 {
		return fmt.Errorf("prevent_reuse must be non-negative, got %d", p.PreventReuse)
	}

	if p.ExpirationDays < 0 {
		return fmt.Errorf("expiration_days must be non-negative, got %d", p.ExpirationDays)
	}

	if p.MinEntropyBits < 0 {
		return fmt.Errorf("min_entropy_bits must be non-negative, got %d", p.MinEntropyBits)
	}

	return nil
}

// WithConfig is a functional option that applies a Config to the LoginService
func WithConfig(config Config) Option {
	return func(ls *LoginService) {
		ls.maxFailedAttempts = config.MaxFailedAttempts
		ls.lockoutDuration = config.LockoutDuration
		ls.magicLinkTokenExpiration = config.MagicLinkTokenExpiration

		// Apply password policy if provided and password manager exists
		if config.PasswordPolicy != nil && ls.passwordManager != nil {
			ls.passwordManager.policy = config.PasswordPolicy
		}
	}
}

// NewLoginServiceWithConfig creates a LoginService with the provided config
// This is a convenience constructor that combines config and functional options
//
// Example:
//
//	config := login.DefaultConfig()
//	config.MaxFailedAttempts = 3
//	config.LockoutDuration = 1 * time.Hour
//
//	service := login.NewLoginServiceWithConfig(
//	    repository,
//	    config,
//	    login.WithNotificationManager(notificationManager),
//	    login.WithUserMapper(userMapper),
//	)
func NewLoginServiceWithConfig(repository LoginRepository, config Config, opts ...Option) (*LoginService, error) {
	// Validate config first
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create password manager with policy
	var passwordManager *PasswordManager
	if config.PasswordPolicy != nil {
		passwordManager = &PasswordManager{
			repository: repository,
			hasher:     NewBcryptHasher(), // Default to bcrypt
			policy:     config.PasswordPolicy,
		}
	} else {
		passwordManager = NewPasswordManagerWithRepository(repository)
	}

	// Create service with defaults
	service := &LoginService{
		repository:               repository,
		passwordManager:          passwordManager,
		maxFailedAttempts:        config.MaxFailedAttempts,
		lockoutDuration:          config.LockoutDuration,
		magicLinkTokenExpiration: config.MagicLinkTokenExpiration,
	}

	// Apply additional options (for dependencies)
	for _, opt := range opts {
		opt(service)
	}

	return service, nil
}
