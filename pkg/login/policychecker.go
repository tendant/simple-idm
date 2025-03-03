package login

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// PasswordPolicy defines the requirements for password complexity
type PasswordPolicy struct {
	MinLength           int
	RequireUppercase    bool
	RequireLowercase    bool
	RequireDigit        bool
	RequireSpecialChar  bool
	DisallowCommonPwds  bool
	MaxRepeatedChars    int
	HistoryCheckCount   int
	ExpirationDays      int
	CommonPasswordsPath string
}

// PasswordPolicyChecker defines the interface for checking password complexity
type PasswordPolicyChecker interface {
	CheckPasswordComplexity(password string) error
	GetPolicy() *PasswordPolicy
}

// DefaultPasswordPolicyChecker implements the PasswordPolicyChecker interface
type DefaultPasswordPolicyChecker struct {
	policy          *PasswordPolicy
	commonPasswords map[string]bool
}

// NewDefaultPasswordPolicyChecker creates a new default password policy checker
func NewDefaultPasswordPolicyChecker(policy *PasswordPolicy, commonPasswords map[string]bool) *DefaultPasswordPolicyChecker {
	if policy == nil {
		policy = DefaultPasswordPolicy()
	}

	if commonPasswords == nil {
		commonPasswords = loadCommonPasswords(policy.CommonPasswordsPath)
	}

	return &DefaultPasswordPolicyChecker{
		policy:          policy,
		commonPasswords: commonPasswords,
	}
}

// CheckPasswordComplexity verifies that a password meets the complexity requirements
func (pc *DefaultPasswordPolicyChecker) CheckPasswordComplexity(password string) error {
	// Check minimum length
	if len(password) < pc.policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", pc.policy.MinLength)
	}

	// Check for uppercase letters if required
	if pc.policy.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return errors.New("password must contain at least one uppercase letter")
	}

	// Check for lowercase letters if required
	if pc.policy.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return errors.New("password must contain at least one lowercase letter")
	}

	// Check for digits if required
	if pc.policy.RequireDigit && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return errors.New("password must contain at least one digit")
	}

	// Check for special characters if required
	if pc.policy.RequireSpecialChar && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return errors.New("password must contain at least one special character")
	}

	// Check for common passwords
	if pc.policy.DisallowCommonPwds && pc.isCommonPassword(password) {
		return errors.New("password is too common, please choose a more secure password")
	}

	// Check for repeated characters
	if pc.policy.MaxRepeatedChars > 0 && hasRepeatedChars(password, pc.policy.MaxRepeatedChars) {
		return fmt.Errorf("password cannot contain more than %d consecutive repeated characters", pc.policy.MaxRepeatedChars)
	}

	return nil
}

func (pc *DefaultPasswordPolicyChecker) isCommonPassword(password string) bool {
	return pc.commonPasswords[strings.ToLower(password)]
}

func hasRepeatedChars(password string, maxRepeated int) bool {
	for i := 0; i < len(password)-maxRepeated+1; i++ {
		if strings.Count(password[i:i+maxRepeated], string(password[i])) == maxRepeated {
			return true
		}
	}
	return false
}

// GetPolicy returns the password policy
func (pc *DefaultPasswordPolicyChecker) GetPolicy() *PasswordPolicy {
	return pc.policy
}

// DefaultPasswordPolicy returns a default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:          8,
		RequireUppercase:   true,
		RequireLowercase:   true,
		RequireDigit:       true,
		RequireSpecialChar: true,
		DisallowCommonPwds: true,
		MaxRepeatedChars:   3,
		HistoryCheckCount:  5,
		ExpirationDays:     90,
	}
}

// loadCommonPasswords loads a list of common passwords from a file or returns a default set
func loadCommonPasswords(filePath string) map[string]bool {
	// This is a small sample - in production, you'd load thousands from a file
	commonPwds := []string{
		"password", "123456", "12345678", "qwerty", "admin",
		"welcome", "login", "abc123", "letmein", "monkey",
	}

	result := make(map[string]bool)
	for _, pwd := range commonPwds {
		result[pwd] = true
	}
	return result
}
