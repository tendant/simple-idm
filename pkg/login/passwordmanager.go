package login

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"

	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/utils"
)

// PasswordVersion represents the version of the password hashing algorithm
type PasswordVersion int

const (
	// PasswordV1 is the original bcrypt implementation
	PasswordV1 PasswordVersion = 1
	
	// PasswordV2 adds a salt prefix to the password before hashing
	PasswordV2 PasswordVersion = 2
	
	// PasswordV3 could use a different algorithm like Argon2id
	PasswordV3 PasswordVersion = 3
	
	// CurrentPasswordVersion is the version that should be used for new passwords
	CurrentPasswordVersion = PasswordV2
)

// PasswordManager handles password-related operations
type PasswordManager struct {
	queries         *logindb.Queries
	policy          *PasswordPolicy
	version         PasswordVersion
	commonPasswords map[string]bool
}

// NewPasswordManager creates a new PasswordManager with the specified policy
func NewPasswordManager(queries *logindb.Queries, policy *PasswordPolicy) *PasswordManager {
	if policy == nil {
		policy = DefaultPasswordPolicy()
	}
	
	return &PasswordManager{
		queries:         queries,
		policy:          policy,
		version:         CurrentPasswordVersion,
		commonPasswords: loadCommonPasswords(policy.CommonPasswordsPath),
	}
}

// PasswordPolicy defines the requirements for password complexity
type PasswordPolicy struct {
	MinLength            int
	RequireUppercase     bool
	RequireLowercase     bool
	RequireDigit         bool
	RequireSpecialChar   bool
	DisallowCommonPwds   bool
	MaxRepeatedChars     int
	HistoryCheckCount    int
	ExpirationDays       int
	CommonPasswordsPath  string
}

// DefaultPasswordPolicy returns a default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:           8,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireDigit:        true,
		RequireSpecialChar:  true,
		DisallowCommonPwds:  true,
		MaxRepeatedChars:    3,
		HistoryCheckCount:   5,
		ExpirationDays:      90,
		CommonPasswordsPath: "",
	}
}

// HashPassword hashes a password with the current version
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	
	// Hash the password using the current version
	return pm.hashPasswordWithVersion(password, pm.version)
}

// hashPasswordWithVersion hashes a password with a specific version
func (pm *PasswordManager) hashPasswordWithVersion(password string, version PasswordVersion) (string, error) {
	var hashedPassword string
	var err error
	
	switch version {
	case PasswordV1:
		// Original bcrypt implementation
		hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		hashedPassword = string(hashedBytes)
		
	case PasswordV2:
		// Add a salt and use a higher cost
		salt := utils.GenerateRandomString(16)
		// Combine salt and password
		saltedPassword := salt + password
		hashedBytes, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost+2)
		if err != nil {
			return "", err
		}
		// Store salt and hash (without version prefix since it's in a separate column)
		hashedPassword = fmt.Sprintf("%s:%s", salt, string(hashedBytes))
		
	case PasswordV3:
		// Future implementation
		return "", errors.New("password version 3 not implemented yet")
		
	default:
		return "", fmt.Errorf("unsupported password version: %d", version)
	}
	
	return hashedPassword, err
}

// CheckPasswordHash checks if the provided password matches the stored hash
func (pm *PasswordManager) CheckPasswordHash(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, errors.New("password and hashed password cannot be empty")
	}
	
	// Detect the version from the hash format
	if strings.Contains(hashedPassword, ":") {
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
	} else {
		// Assume version 1 (original bcrypt) if no salt prefix
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, nil // Password doesn't match, but not an error
			}
			return false, err // Some other error occurred
		}
		
		return true, nil
	}
}

// VerifyPasswordWithVersion verifies a password against a hash with a known version
func (pm *PasswordManager) VerifyPasswordWithVersion(password, hashedPassword string, version PasswordVersion) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, errors.New("password and hashed password cannot be empty")
	}
	
	switch version {
	case PasswordV1:
		// Original bcrypt implementation
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, nil
			}
			return false, err
		}
		return true, nil
		
	case PasswordV2:
		// Version 2 format: salt:hash
		parts := strings.SplitN(hashedPassword, ":", 2)
		if len(parts) != 2 {
			return false, errors.New("invalid v2 password format")
		}
		
		salt := parts[0]
		hash := parts[1]
		
		// Combine salt and password for verification
		saltedPassword := salt + password
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(saltedPassword))
		if err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, nil
			}
			return false, err
		}
		return true, nil
		
	case PasswordV3:
		// Future implementation
		return false, errors.New("password version 3 not implemented yet")
		
	default:
		return false, fmt.Errorf("unsupported password version: %d", version)
	}
}

// UpgradePasswordVersionIfNeeded checks if the password hash needs to be upgraded
// and returns true if an upgrade was performed
func (pm *PasswordManager) UpgradePasswordVersionIfNeeded(ctx context.Context, userID string, password string, currentHash string, currentVersion PasswordVersion) (bool, error) {
	// If the current version is less than the target version, upgrade
	if currentVersion < pm.version {
		// Hash the password with the current version
		newHash, err := pm.hashPasswordWithVersion(password, pm.version)
		if err != nil {
			return false, fmt.Errorf("failed to upgrade password hash: %w", err)
		}
		
		// Update the password hash and version in the database
		err = pm.queries.UpdateUserPasswordAndVersion(ctx, logindb.UpdateUserPasswordAndVersionParams{
			ID:             utils.ParseUUID(userID),
			Password:       newHash,
			PasswordVersion: int32(pm.version),
		})
		if err != nil {
			return false, fmt.Errorf("failed to update password hash: %w", err)
		}
		
		// Add the old password to history
		err = pm.addPasswordToHistory(ctx, userID, currentHash, currentVersion)
		if err != nil {
			// Log but don't fail the upgrade
			slog.Error("Failed to add password to history", "error", err)
		}
		
		slog.Info("Upgraded password hash version", 
			"userID", userID, 
			"fromVersion", currentVersion, 
			"toVersion", pm.version)
		
		return true, nil
	}
	
	return false, nil
}

// addPasswordToHistory adds a password to the password history table
func (pm *PasswordManager) addPasswordToHistory(ctx context.Context, userID, passwordHash string, version PasswordVersion) error {
	// Add the password to the history table
	err := pm.queries.AddPasswordToHistory(ctx, logindb.AddPasswordToHistoryParams{
		LoginID:         utils.ParseUUID(userID),
		PasswordHash:    passwordHash,
		PasswordVersion: int32(version),
	})
	if err != nil {
		return fmt.Errorf("failed to add password to history: %w", err)
	}
	return nil
}

// AuthenticateAndUpgrade verifies a password and upgrades the hash if needed
func (pm *PasswordManager) AuthenticateAndUpgrade(ctx context.Context, userID, password, currentHash string, currentVersion PasswordVersion) (bool, error) {
	// First verify the password with the known version
	valid, err := pm.VerifyPasswordWithVersion(password, currentHash, currentVersion)
	if err != nil {
		return false, err
	}
	
	if !valid {
		return false, nil
	}
	
	// If password is valid, check if we need to upgrade the hash version
	_, err = pm.UpgradePasswordVersionIfNeeded(ctx, userID, password, currentHash, currentVersion)
	if err != nil {
		// Log the error but don't fail authentication
		slog.Error("Failed to upgrade password hash", "error", err)
	}
	
	return true, nil
}

// CheckPasswordHistory verifies that a new password hasn't been used recently
// Returns an error if the password has been used before
func (pm *PasswordManager) CheckPasswordHistory(ctx context.Context, userID, newPassword string) error {
	// If history checking is disabled, always pass
	if pm.policy.HistoryCheckCount <= 0 {
		return nil
	}
	
	// First check against the current password
	login, err := pm.queries.GetLoginById(ctx, utils.ParseUUID(userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // No user found, so no history to check against
		}
		return fmt.Errorf("failed to get user for history check: %w", err)
	}
	
	// Get the current password version
	passwordVersion, err := pm.queries.GetUserPasswordVersion(ctx, utils.ParseUUID(userID))
	if err != nil {
		// If there's an error getting the version, assume version 1
		slog.Warn("Could not get password version, assuming version 1", "error", err)
		passwordVersion = 1
	}
	
	// Check if the new password matches the current password
	match, err := pm.VerifyPasswordWithVersion(newPassword, string(login.Password), PasswordVersion(passwordVersion))
	if err != nil {
		return fmt.Errorf("error checking against current password: %w", err)
	}
	
	if match {
		return errors.New("new password cannot be the same as your current password")
	}
	
	// Now check against password history
	passwordHistory, err := pm.queries.GetPasswordHistory(ctx, logindb.GetPasswordHistoryParams{
		LoginID: utils.ParseUUID(userID),
		Limit:   int32(pm.policy.HistoryCheckCount),
	})
	if err != nil {
		// If there's an error getting history, log it but continue
		slog.Error("Failed to get password history", "error", err)
		return nil
	}
	
	// Check each historical password
	for _, historyItem := range passwordHistory {
		match, err := pm.VerifyPasswordWithVersion(
			newPassword, 
			historyItem.PasswordHash, 
			PasswordVersion(historyItem.PasswordVersion),
		)
		if err != nil {
			// Log error but continue checking other passwords
			slog.Error("Error checking password history item", "error", err)
			continue
		}
		
		if match {
			return errors.New("new password cannot match any of your recent passwords")
		}
	}
	
	return nil
}

// InitPasswordReset generates a reset token and stores it in the database
func (pm *PasswordManager) InitPasswordReset(ctx context.Context, loginID string) (string, error) {
	// Generate a secure random token
	resetToken := utils.GenerateRandomString(32)
	
	// Set expiration time (24 hours from now)
	expireAt := pgtype.Timestamptz{}
	err := expireAt.Scan(time.Now().Add(24 * time.Hour))
	if err != nil {
		return "", fmt.Errorf("failed to create expiry time: %w", err)
	}
	
	// Store the token in the database
	err = pm.queries.InitPasswordResetToken(ctx, logindb.InitPasswordResetTokenParams{
		LoginID:  utils.ParseUUID(loginID),
		Token:    resetToken,
		ExpireAt: expireAt,
	})
	if err != nil {
		slog.Error("Failed to save reset token", "err", err)
		return "", err
	}
	
	return resetToken, nil
}

// ValidateResetToken checks if a reset token is valid and not expired
func (pm *PasswordManager) ValidateResetToken(ctx context.Context, token string) (string, error) {
	// Validate token and get user info
	tokenInfo, err := pm.queries.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("invalid or expired reset token")
	}
	
	return tokenInfo.LoginID.String(), nil
}

// ResetPassword changes a user's password using a valid reset token
func (pm *PasswordManager) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate token and get user info
	tokenInfo, err := pm.queries.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}
	
	// Check if the new password meets complexity requirements
	if err := pm.CheckPasswordComplexity(newPassword); err != nil {
		return err
	}
	
	// Get current password and version for history
	login, err := pm.queries.GetLoginById(ctx, tokenInfo.LoginID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("failed to get current password: %w", err)
	}
	
	// If we found the login, check password history
	if err == nil && pm.policy.HistoryCheckCount > 0 {
		if err := pm.CheckPasswordHistory(ctx, tokenInfo.LoginID.String(), newPassword); err != nil {
			return err
		}
		
		// Store the old password in history
		passwordVersion, err := pm.queries.GetUserPasswordVersion(ctx, tokenInfo.LoginID)
		if err == nil {
			// Only add to history if we could get the version
			err = pm.addPasswordToHistory(ctx, tokenInfo.LoginID.String(), string(login.Password), PasswordVersion(passwordVersion))
			if err != nil {
				// Log but continue
				slog.Error("Failed to add password to history", "error", err)
			}
		}
	}
	
	// Hash the new password using the current version
	hashedPassword, err := pm.hashPasswordWithVersion(newPassword, pm.version)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	
	// Update password and version
	err = pm.queries.UpdateUserPasswordAndVersion(ctx, logindb.UpdateUserPasswordAndVersionParams{
		ID:              tokenInfo.LoginID,
		Password:        hashedPassword,
		PasswordVersion: int32(pm.version),
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	
	// Mark token as used
	err = pm.queries.MarkPasswordResetTokenUsed(ctx, token)
	if err != nil {
		slog.Error("Failed to mark token as used", "err", err)
		// Don't return error as password was successfully reset
	}
	
	return nil
}

// ChangePassword changes a user's password after verifying the current password
func (pm *PasswordManager) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	// Get the current user info
	login, err := pm.queries.GetLoginById(ctx, utils.ParseUUID(userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("user not found")
		}
		return err
	}
	
	// Get the password version
	passwordVersion, err := pm.queries.GetUserPasswordVersion(ctx, utils.ParseUUID(userID))
	if err != nil {
		// If there's an error getting the version, assume version 1
		slog.Warn("Could not get password version, assuming version 1", "error", err)
		passwordVersion = 1
	}
	
	// Verify the current password
	match, err := pm.VerifyPasswordWithVersion(currentPassword, string(login.Password), PasswordVersion(passwordVersion))
	if err != nil {
		return err
	}
	if !match {
		return errors.New("current password is incorrect")
	}
	
	// Check if the new password meets complexity requirements
	if err := pm.CheckPasswordComplexity(newPassword); err != nil {
		return err
	}
	
	// Check password history if enabled
	if pm.policy.HistoryCheckCount > 0 {
		if err := pm.CheckPasswordHistory(ctx, userID, newPassword); err != nil {
			return err
		}
		
		// Add the current password to history
		err = pm.addPasswordToHistory(ctx, userID, string(login.Password), PasswordVersion(passwordVersion))
		if err != nil {
			// Log but continue
			slog.Error("Failed to add password to history", "error", err)
		}
	}
	
	// Hash the new password using the current version
	hashedPassword, err := pm.hashPasswordWithVersion(newPassword, pm.version)
	if err != nil {
		return err
	}
	
	// Update the password hash and version in the database
	err = pm.queries.UpdateUserPasswordAndVersion(ctx, logindb.UpdateUserPasswordAndVersionParams{
		ID:              utils.ParseUUID(userID),
		Password:        hashedPassword,
		PasswordVersion: int32(pm.version),
	})
	if err != nil {
		return err
	}
	
	return nil
}

// IsPasswordExpired checks if a password has expired based on policy
func (pm *PasswordManager) IsPasswordExpired(ctx context.Context, loginID string) (bool, error) {
	// In a real implementation, you would:
	// 1. Retrieve the last password change timestamp
	// 2. Compare with the current time and password expiration policy
	
	// This is a placeholder implementation
	return false, nil
}

// GenerateRandomPassword creates a random password that meets complexity requirements
func (pm *PasswordManager) GenerateRandomPassword() string {
	// Define character sets
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	special := "!@#$%^&*()-_=+[]{}|;:,.<>?"
	
	// Create a password with at least one character from each required set
	var password strings.Builder
	
	if pm.policy.RequireUppercase {
		password.WriteByte(uppercase[utils.RandomInt(len(uppercase))])
	}
	if pm.policy.RequireLowercase {
		password.WriteByte(lowercase[utils.RandomInt(len(lowercase))])
	}
	if pm.policy.RequireDigit {
		password.WriteByte(digits[utils.RandomInt(len(digits))])
	}
	if pm.policy.RequireSpecialChar {
		password.WriteByte(special[utils.RandomInt(len(special))])
	}
	
	// Calculate how many more characters we need
	remainingLength := pm.policy.MinLength - password.Len()
	
	// Build a character set with all allowed characters
	allChars := ""
	if pm.policy.RequireUppercase {
		allChars += uppercase
	}
	if pm.policy.RequireLowercase {
		allChars += lowercase
	}
	if pm.policy.RequireDigit {
		allChars += digits
	}
	if pm.policy.RequireSpecialChar {
		allChars += special
	}
	
	// Add random characters until we reach the minimum length
	for i := 0; i < remainingLength; i++ {
		password.WriteByte(allChars[utils.RandomInt(len(allChars))])
	}
	
	// Shuffle the password to avoid predictable patterns
	passwordRunes := []rune(password.String())
	utils.ShuffleRunes(passwordRunes)
	
	return string(passwordRunes)
}

// loadCommonPasswords loads a list of common passwords from a file or returns a default set
func loadCommonPasswords(filePath string) map[string]bool {
	// This is a small sample - in production, you'd load thousands from a file
	commonPwds := []string{
		"password", "123456", "12345678", "qwerty", "admin",
		"welcome", "password123", "abc123", "letmein", "monkey",
	}
	
	// TODO: If filePath is provided, load passwords from the file
	
	result := make(map[string]bool)
	for _, pwd := range commonPwds {
		result[pwd] = true
	}
	return result
}

// CheckPasswordComplexity verifies that a password meets the complexity requirements
func (pm *PasswordManager) CheckPasswordComplexity(password string) error {
	// Check minimum length
	if len(password) < pm.policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", pm.policy.MinLength)
	}
	
	// Check for uppercase letters if required
	if pm.policy.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return errors.New("password must contain at least one uppercase letter")
	}
	
	// Check for lowercase letters if required
	if pm.policy.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return errors.New("password must contain at least one lowercase letter")
	}
	
	// Check for digits if required
	if pm.policy.RequireDigit && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return errors.New("password must contain at least one digit")
	}
	
	// Check for special characters if required
	if pm.policy.RequireSpecialChar && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return errors.New("password must contain at least one special character")
	}
	
	// Check for repeated characters
	if pm.policy.MaxRepeatedChars > 0 {
		for i := 0; i < len(password)-pm.policy.MaxRepeatedChars+1; i++ {
			if strings.Count(password[i:i+pm.policy.MaxRepeatedChars], string(password[i])) == pm.policy.MaxRepeatedChars {
				return fmt.Errorf("password cannot contain %d or more repeated characters", pm.policy.MaxRepeatedChars)
			}
		}
	}
	
	// Check against common passwords
	if pm.policy.DisallowCommonPwds && pm.commonPasswords[strings.ToLower(password)] {
		return errors.New("password is too common and easily guessable")
	}
	
	return nil
}
