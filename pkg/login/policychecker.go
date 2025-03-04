package login

import (
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

// PasswordValidationErrors represents a collection of password validation errors
type PasswordValidationErrors []string

// Error implements the error interface
func (e PasswordValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}

	if len(e) == 1 {
		return e[0]
	}

	var sb strings.Builder
	sb.WriteString("Password validation failed:\n")
	for i, err := range e {
		sb.WriteString(fmt.Sprintf("- %s", err))
		if i < len(e)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// PasswordPolicyChecker defines the interface for checking password complexity
type PasswordPolicyChecker interface {
	CheckPasswordComplexity(password string) PasswordValidationErrors
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
func (pc *DefaultPasswordPolicyChecker) CheckPasswordComplexity(password string) PasswordValidationErrors {
	var errors PasswordValidationErrors

	// Check minimum length
	if len(password) < pc.policy.MinLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters long", pc.policy.MinLength))
	}

	// Check for uppercase letters if required
	if pc.policy.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		errors = append(errors, "password must contain at least one uppercase letter")
	}

	// Check for lowercase letters if required
	if pc.policy.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		errors = append(errors, "password must contain at least one lowercase letter")
	}

	// Check for digits if required
	if pc.policy.RequireDigit && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		errors = append(errors, "password must contain at least one digit")
	}

	// Check for special characters if required
	if pc.policy.RequireSpecialChar && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		errors = append(errors, "password must contain at least one special character")
	}

	// Check for common passwords
	if pc.policy.DisallowCommonPwds && pc.isCommonPassword(password) {
		errors = append(errors, "password is too common, please choose a more secure password")
	}

	// Check for repeated characters
	if pc.policy.MaxRepeatedChars > 0 && hasRepeatedChars(password, pc.policy.MaxRepeatedChars) {
		errors = append(errors, fmt.Sprintf("password cannot contain more than %d consecutive repeated characters", pc.policy.MaxRepeatedChars))
	}

	return errors
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
