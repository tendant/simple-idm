package login

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

// PasswordManager handles password-related operations
type PasswordManager struct {
	repository     LoginRepository
	policyChecker  PasswordPolicyChecker
	hasherFactory  PasswordHasherFactory
	currentVersion PasswordVersion
}

// NewPasswordManager creates a new password manager with the specified queries
func NewPasswordManager(queries *logindb.Queries) *PasswordManager {
	// Create a repository that wraps the queries
	repository := NewPostgresLoginRepository(queries)
	return &PasswordManager{
		repository:     repository,
		policyChecker:  NewDefaultPasswordPolicyChecker(nil, nil),
		hasherFactory:  NewDefaultPasswordHasherFactory(CurrentPasswordVersion),
		currentVersion: CurrentPasswordVersion,
	}
}

// NewPasswordManagerWithRepository creates a new password manager with the specified repository
func NewPasswordManagerWithRepository(repository LoginRepository) *PasswordManager {
	return &PasswordManager{
		repository:     repository,
		policyChecker:  NewDefaultPasswordPolicyChecker(nil, nil),
		hasherFactory:  NewDefaultPasswordHasherFactory(CurrentPasswordVersion),
		currentVersion: CurrentPasswordVersion,
	}
}

// WithHasherFactory sets a custom password hasher factory
func (pm *PasswordManager) WithHasherFactory(factory PasswordHasherFactory) *PasswordManager {
	pm.hasherFactory = factory
	return pm
}

// WithPolicyChecker sets a custom password policy checker
func (pm *PasswordManager) WithPolicyChecker(checker PasswordPolicyChecker) *PasswordManager {
	pm.policyChecker = checker
	return pm
}

// HashPassword hashes a password with the current version
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	return pm.hashPasswordWithVersion(password, pm.currentVersion)
}

// hashPasswordWithVersion hashes a password with a specific version
func (pm *PasswordManager) hashPasswordWithVersion(password string, version PasswordVersion) (string, error) {
	hasher, err := pm.hasherFactory.GetHasher(version)
	if err != nil {
		return "", err
	}

	return hasher.Hash(password)
}

// CheckPasswordHash checks if the provided password matches the stored hash
func (pm *PasswordManager) CheckPasswordHash(password, hashedPassword string, version PasswordVersion) (bool, error) {
	hasher, err := pm.hasherFactory.GetHasher(version)
	if err != nil {
		return false, err
	}

	return hasher.Verify(password, hashedPassword)
}

// VerifyPasswordWithVersion verifies a password against a hash with a specific version
func (pm *PasswordManager) VerifyPasswordWithVersion(password, hashedPassword string, version PasswordVersion) (bool, error) {
	return pm.CheckPasswordHash(password, hashedPassword, version)
}

// UpgradePasswordVersionIfNeeded checks if the password hash needs to be upgraded
// and returns true if an upgrade was performed
func (pm *PasswordManager) UpgradePasswordVersionIfNeeded(ctx context.Context, loginID uuid.UUID, password string, currentHash string, currentVersion PasswordVersion) (bool, error) {
	// If the current version is less than the target version, upgrade
	if currentVersion < pm.currentVersion {
		// Hash the password with the current version
		newHash, err := pm.hashPasswordWithVersion(password, pm.currentVersion)
		if err != nil {
			return false, fmt.Errorf("failed to upgrade password hash: %w", err)
		}

		// Update the password hash and version in the database
		err = pm.repository.UpdateUserPasswordAndVersion(ctx, PasswordParams{
			ID:              loginID,
			Password:        []byte(newHash),
			PasswordVersion: int32(pm.currentVersion),
		})
		if err != nil {
			return false, fmt.Errorf("failed to update password hash: %w", err)
		}

		// Add the old password to history
		err = pm.addPasswordToHistory(ctx, loginID, currentHash, currentVersion)
		if err != nil {
			// Log but don't fail the upgrade
			slog.Error("Failed to add password to history", "error", err)
		}

		slog.Info("Upgraded password hash version",
			"loginID", loginID,
			"fromVersion", currentVersion,
			"toVersion", pm.currentVersion)

		return true, nil
	}

	return false, nil
}

// addPasswordToHistory adds a password to the password history table
func (pm *PasswordManager) addPasswordToHistory(ctx context.Context, loginID uuid.UUID, passwordHash string, version PasswordVersion) error {
	// Add the password to the history table
	err := pm.repository.AddPasswordToHistory(ctx, PasswordToHistoryParams{
		LoginID:         loginID,
		PasswordHash:    []byte(passwordHash),
		PasswordVersion: int32(version),
	})
	if err != nil {
		return fmt.Errorf("failed to add password to history: %w", err)
	}
	return nil
}

// AuthenticateAndUpgrade verifies a password and upgrades the hash if needed
func (pm *PasswordManager) AuthenticateAndUpgrade(ctx context.Context, loginID uuid.UUID, password, currentHash string, currentVersion PasswordVersion) (bool, error) {
	// First verify the password with the known version
	valid, err := pm.VerifyPasswordWithVersion(password, currentHash, currentVersion)
	if err != nil {
		slog.Error("Failed to verify password", "error", err)
		return false, err
	}

	if !valid {
		slog.Error("Invalid password")
		return false, nil
	}

	// If password is valid, check if we need to upgrade the hash version
	_, err = pm.UpgradePasswordVersionIfNeeded(ctx, loginID, password, currentHash, currentVersion)
	if err != nil {
		// Log the error but don't fail authentication
		slog.Error("Failed to upgrade password hash", "error", err)
	}

	return true, nil
}

// CheckPasswordHistory verifies that a new password hasn't been used recently
// Returns an error if the password has been used before
func (pm *PasswordManager) CheckPasswordHistory(ctx context.Context, loginID, newPassword string) error {
	// If history checking is disabled or no policy checker, always pass
	if pm.policyChecker.GetPolicy().HistoryCheckCount <= 0 {
		return nil
	}

	// First check against the current password
	login, err := pm.repository.GetLoginById(ctx, utils.ParseUUID(loginID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // No user found, so no history to check against
		}
		return fmt.Errorf("failed to get user for history check: %w", err)
	}

	// Get the current password version
	version, isValid, err := pm.repository.GetPasswordVersion(ctx, login.ID)
	if err != nil || !isValid {
		// If there's an error getting the version or it's not valid, assume version 1
		slog.Warn("Could not get password version, assuming version 1", "error", err)
		version = 1
	}

	// Check if the new password matches the current password
	match, err := pm.VerifyPasswordWithVersion(newPassword, string(login.Password), PasswordVersion(version))
	if err != nil {
		return fmt.Errorf("error checking against current password: %w", err)
	}

	if match {
		return errors.New("new password cannot be the same as your current password")
	}

	// Now check against password history
	passwordHistory, err := pm.repository.GetPasswordHistory(ctx, PasswordHistoryParams{
		LoginID: login.ID,
		Limit:   int32(pm.policyChecker.GetPolicy().HistoryCheckCount),
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
			string(historyItem.PasswordHash),
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
func (pm *PasswordManager) InitPasswordReset(ctx context.Context, loginID uuid.UUID) (string, error) {
	// Generate a secure random token
	resetToken := utils.GenerateRandomString(32)

	// Set expiration time (24 hours from now)
	expireAt := pgtype.Timestamptz{}
	err := expireAt.Scan(time.Now().UTC().Add(24 * time.Hour))
	if err != nil {
		slog.Error("Failed to create expiry time", "err", err)
		return "", fmt.Errorf("failed to create expiry time: %w", err)
	}

	err = pm.repository.ExpirePasswordResetToken(ctx, loginID)
	if err != nil {
		slog.Error("Failed to expire existing reset token", "err", err)
		return "", err
	}

	// Store the token in the database
	err = pm.repository.InitPasswordResetToken(ctx, PasswordResetTokenParams{
		LoginID:  loginID,
		Token:    resetToken,
		ExpireAt: time.Time(expireAt.Time),
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
	tokenInfo, err := pm.repository.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		slog.Error("Failed to validate reset token", "err", err)
		return "", fmt.Errorf("invalid or expired reset token")
	}

	return tokenInfo.LoginID.String(), nil
}

// ResetPassword changes a user's password using a valid reset token
func (pm *PasswordManager) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate token and get user info
	tokenInfo, err := pm.repository.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		slog.Error("Failed to validate reset token", "err", err)
		return errors.New("invalid or expired reset token")
	}
	slog.Info("token validated")

	// Check if the new password meets complexity requirements
	if err := pm.CheckPasswordComplexity(newPassword); err != nil {
		slog.Error("Failed to check password complexity", "err", err)
		return err
	}
	slog.Info("Password complexity checked")

	// Get current password and version for history
	login, err := pm.repository.GetLoginById(ctx, tokenInfo.LoginID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("Failed to get current password", "err", err)
		return fmt.Errorf("failed to get current password: %w", err)
	}

	// If we found the login, check password history
	if err == nil && pm.policyChecker.GetPolicy().HistoryCheckCount > 0 {
		if err := pm.CheckPasswordHistory(ctx, tokenInfo.LoginID.String(), newPassword); err != nil {
			slog.Error("Failed to check password history", "err", err)
			return err
		}

		// Store the old password in history
		version, isValid, err := pm.repository.GetPasswordVersion(ctx, tokenInfo.LoginID)
		if err == nil && isValid {
			// Only add to history if we could get the version
			err = pm.addPasswordToHistory(ctx, tokenInfo.LoginID, string(login.Password), PasswordVersion(version))
			if err != nil {
				// Log but continue
				slog.Error("Failed to add password to history", "error", err)
			}
		}
		slog.Info("password version", "version", version)
	}

	slog.Info("Password history checked")

	// Hash the new password using the current version
	slog.Info("Password Version in Password Manager", "version", pm.currentVersion)
	hashedPassword, err := pm.hashPasswordWithVersion(newPassword, pm.currentVersion)
	if err != nil {
		slog.Error("Failed to hash password", "err", err)
		return fmt.Errorf("failed to hash password: %w", err)
	}
	slog.Info("password hashed")

	// Update password and version
	err = pm.repository.UpdateUserPasswordAndVersion(ctx, PasswordParams{
		ID:              tokenInfo.LoginID,
		Password:        []byte(hashedPassword),
		PasswordVersion: int32(pm.currentVersion),
	})
	if err != nil {
		slog.Error("Failed to update password", "err", err)
		return fmt.Errorf("failed to update password: %w", err)
	}
	slog.Info("Password updated")

	// Mark token as used
	err = pm.repository.MarkPasswordResetTokenUsed(ctx, token)
	if err != nil {
		slog.Error("Failed to mark token as used", "err", err)
		// Don't return error as password was successfully reset
	}
	slog.Info("Token marked as used")

	err = pm.repository.UpdatePasswordResetRequired(ctx, tokenInfo.LoginID, false)
	if err != nil {
		slog.Error("Failed to update password reset required", "err", err)
		return err
	}
	slog.Info("Updated password reset required to false")

	return nil
}

// ChangePassword changes a user's password after verifying the current password
func (pm *PasswordManager) ChangePassword(ctx context.Context, loginID, currentPassword, newPassword string) error {
	// Get the current user info
	login, err := pm.repository.GetLoginById(ctx, utils.ParseUUID(loginID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("user not found")
		}
		return err
	}
	slog.Info("User found", "user", login.Username)

	// Get the password version
	version, isValid, err := pm.repository.GetPasswordVersion(ctx, login.ID)
	if err != nil || !isValid {
		// If there's an error getting the version or it's not valid, assume version 1
		slog.Warn("Could not get password version, assuming version 1", "error", err)
		version = 1
	}

	slog.Info("Password version", "version", version)

	// Verify the current password
	match, err := pm.VerifyPasswordWithVersion(currentPassword, string(login.Password), PasswordVersion(version))
	if err != nil {
		slog.Error("Failed to verify password", "err", err)
		return err
	}
	if !match {
		slog.Error("Current password is incorrect")
		return errors.New("current password is incorrect")
	}

	slog.Info("Current password is correct")

	// Check if the new password meets complexity requirements
	if err := pm.CheckPasswordComplexity(newPassword); err != nil {
		slog.Error("Failed to check password complexity", "err", err)
		return err
	}
	slog.Info("New password is valid")

	// Check password history if enabled
	// if pm.policyChecker.GetPolicy().HistoryCheckCount > 0 {
	// 	if err := pm.CheckPasswordHistory(ctx, userID, newPassword); err != nil {
	// 		return err
	// 	}

	// 	// Add the current password to history
	// 	err = pm.addPasswordToHistory(ctx, login.LoginID, string(login.Password), PasswordVersion(passwordVersion.Int32))
	// 	if err != nil {
	// 		// Log but continue
	// 		slog.Error("Failed to add password to history", "error", err)
	// 		return err
	// 	}
	// }

	// Hash the new password using the current version
	hashedPassword, err := pm.hashPasswordWithVersion(newPassword, pm.currentVersion)
	if err != nil {
		slog.Error("Failed to hash password", "err", err)
		return err
	}

	slog.Info("password hashed")

	// Update the password hash and version in the database
	err = pm.repository.UpdateUserPasswordAndVersion(ctx, PasswordParams{
		ID:              login.ID,
		Password:        []byte(hashedPassword),
		PasswordVersion: int32(pm.currentVersion),
	})
	if err != nil {
		slog.Error("Failed to update password and version", "err", err)
		return err
	}
	slog.Info("Updated password and version")

	err = pm.repository.UpdatePasswordResetRequired(ctx, login.ID, false)
	if err != nil {
		slog.Error("Failed to update password reset required", "err", err)
		return err
	}
	slog.Info("Updated password reset required to false")

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
	uppercase := "ABCDEFGHJKLMNPQRSTUVWXYZ"  // Excluding I and O which can be confused with 1 and 0
	lowercase := "abcdefghijkmnopqrstuvwxyz" // Excluding l which can be confused with 1
	digits := "23456789"                     // Excluding 0 and 1 which can be confused with O and l
	special := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	// Create a password with at least one character from each required set
	var password strings.Builder

	// Use policy settings if available
	minLength := 8
	requireUppercase := true
	requireLowercase := true
	requireDigit := true
	requireSpecialChar := true

	if pm.policyChecker != nil {
		minLength = pm.policyChecker.GetPolicy().MinLength
		requireUppercase = pm.policyChecker.GetPolicy().RequireUppercase
		requireLowercase = pm.policyChecker.GetPolicy().RequireLowercase
		requireDigit = pm.policyChecker.GetPolicy().RequireDigit
		requireSpecialChar = pm.policyChecker.GetPolicy().RequireSpecialChar
	}

	if requireUppercase {
		password.WriteByte(uppercase[utils.RandomInt(len(uppercase))])
	}
	if requireLowercase {
		password.WriteByte(lowercase[utils.RandomInt(len(lowercase))])
	}
	if requireDigit {
		password.WriteByte(digits[utils.RandomInt(len(digits))])
	}
	if requireSpecialChar {
		password.WriteByte(special[utils.RandomInt(len(special))])
	}

	// Calculate how many more characters we need
	remainingLength := minLength - password.Len()

	// Build a character set with all allowed characters
	allChars := ""
	if requireUppercase {
		allChars += uppercase
	}
	if requireLowercase {
		allChars += lowercase
	}
	if requireDigit {
		allChars += digits
	}
	if requireSpecialChar {
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

// CheckPasswordComplexity verifies that a password meets the complexity requirements
func (pm *PasswordManager) CheckPasswordComplexity(password string) error {
	if pm.policyChecker == nil {
		return errors.New("no password policy checker configured")
	}

	validationErrors := pm.policyChecker.CheckPasswordComplexity(password)
	if len(validationErrors) > 0 {
		return validationErrors
	}

	return nil
}

// GetPolicy returns the current password policy
func (pm *PasswordManager) GetPolicy() *PasswordPolicy {
	return pm.policyChecker.GetPolicy()
}
