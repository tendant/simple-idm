package profile

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"github.com/tendant/simple-idm/pkg/utils"
	"github.com/xlzd/gotp"
	"golang.org/x/exp/slog"
)

type ProfileService struct {
	queries      *profiledb.Queries
	loginService *login.LoginService
}

func NewProfileService(queries *profiledb.Queries, loginService *login.LoginService) *ProfileService {
	return &ProfileService{
		queries:      queries,
		loginService: loginService,
	}
}

type UpdateUsernameParams struct {
	UserId          uuid.UUID
	CurrentPassword string
	NewUsername     string
}

// UpdateUsername updates a user's username after verifying their password
func (s *ProfileService) UpdateUsername(ctx context.Context, params UpdateUsernameParams) error {
	// Get the user to verify they exist and check password
	user, err := s.queries.GetUserById(ctx, params.UserId)
	if err != nil {
		slog.Error("Failed to find user", "uuid", params.UserId, "err", err)
		return fmt.Errorf("user not found")
	}

	// Verify the current password
	match, err := s.loginService.CheckPasswordHash(params.CurrentPassword, string(user.Password), login.PasswordV1)
	if err != nil || !match {
		slog.Error("Invalid current password", "uuid", params.UserId)
		return fmt.Errorf("invalid current password")
	}

	// Check if the new username is already taken
	existingUsers, err := s.queries.FindUserByUsername(ctx, sql.NullString{String: params.NewUsername, Valid: true})
	if err != nil {
		slog.Error("Failed to check username availability", "err", err)
		return fmt.Errorf("internal error")
	}
	if len(existingUsers) > 0 {
		return fmt.Errorf("username already taken")
	}

	// Update the username
	err = s.queries.UpdateUsername(ctx, profiledb.UpdateUsernameParams{
		ID:       params.UserId,
		Username: sql.NullString{String: params.NewUsername, Valid: true},
	})
	if err != nil {
		slog.Error("Failed to update username", "uuid", params.UserId, "err", err)
		return fmt.Errorf("failed to update username")
	}

	return nil
}

type UpdatePasswordParams struct {
	UserUuid        uuid.UUID
	CurrentPassword string
	NewPassword     string
}

// UpdatePassword updates a user's password after verifying their current password
func (s *ProfileService) UpdatePassword(ctx context.Context, params UpdatePasswordParams) error {
	// Get the user to verify they exist
	user, err := s.queries.GetUserById(ctx, params.UserUuid)
	if err != nil {
		slog.Error("Failed to find user", "uuid", params.UserUuid, "err", err)
		return fmt.Errorf("user not found")
	}

	slog.Info("Updating password for user", "uuid", params.UserUuid)

	// Check if the user has a login entry - this function may not exist, so handle the error gracefully
	var loginID uuid.UUID
	var hasLoginID bool

	// Try to get login ID - this is a new function that might not exist yet
	loginID, err = s.queries.GetLoginIDByUserID(ctx, params.UserUuid)
	if err == nil {
		hasLoginID = true
		slog.Info("User has login entry", "uuid", params.UserUuid, "loginID", loginID)
	} else {
		slog.Error("User does not have login entry", "uuid", params.UserUuid, "err", err)
		return err
	}

	if hasLoginID {
		// For users with login entries, use the LoginService's ChangePassword method
		slog.Info("Using LoginService.ChangePassword for user with login entry", "uuid", params.UserUuid)
		err = s.loginService.ChangePassword(
			ctx,
			loginID.String(),
			params.CurrentPassword,
			params.NewPassword,
		)
		if err != nil {
			slog.Error("Failed to change password", "uuid", params.UserUuid, "loginID", loginID, "err", err)
			return err
		}

		return nil
	}

	// Legacy path for users without login entries
	slog.Info("Using legacy path for user without login entry", "uuid", params.UserUuid)

	// Verify the current password
	match, err := s.loginService.CheckPasswordHash(params.CurrentPassword, string(user.Password), login.PasswordV1)
	if err != nil || !match {
		slog.Error("Invalid current password", "uuid", params.UserUuid)
		return fmt.Errorf("invalid current password")
	}

	// Check password complexity
	if err := s.loginService.CheckPasswordComplexity(params.NewPassword); err != nil {
		slog.Error("Password doesn't meet complexity requirements", "err", err)
		return err
	}

	// Hash the new password
	hashedPassword, err := s.loginService.HashPassword(params.NewPassword)
	if err != nil {
		slog.Error("Failed to hash new password", "err", err)
		return fmt.Errorf("failed to process new password")
	}

	// Update the password in the database
	err = s.queries.UpdateUserPassword(ctx, profiledb.UpdateUserPasswordParams{
		ID:       params.UserUuid,
		Password: []byte(hashedPassword),
	})
	if err != nil {
		slog.Error("Failed to update password", "uuid", params.UserUuid, "err", err)
		return fmt.Errorf("failed to update password")
	}

	return nil
}

// Disable2FA disables 2FA for a user after verifying their password and 2FA code
func (s ProfileService) Disable2FA(ctx context.Context, userUUID uuid.UUID, currentPassword string, code string) error {
	// Get the user to verify password
	user, err := s.queries.FindUserByUsername(ctx, utils.ToNullString(userUUID.String()))
	if err != nil || len(user) == 0 {
		return fmt.Errorf("user not found")
	}

	// TODO: Verify password using bcrypt
	// TODO: Verify 2FA code using current secret

	// Disable 2FA
	return s.queries.Disable2FA(ctx, userUUID)
}

// Enable2FA enables 2FA for a user and generates backup codes
func (s ProfileService) Enable2FA(ctx context.Context, userUUID uuid.UUID, secret string, code string) ([]string, error) {
	// Verify the code is valid for the secret
	totp := gotp.NewDefaultTOTP(secret)
	if !totp.Verify(code, time.Now().Unix()) {
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// Generate backup codes (8 random codes)
	backupCodes := make([]string, 8)
	for i := range backupCodes {
		bytes := make([]byte, 4)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate backup codes: %w", err)
		}
		backupCodes[i] = hex.EncodeToString(bytes)
	}

	// Enable 2FA in database
	params := profiledb.Enable2FAParams{
		Column1: secret,
		Column2: backupCodes,
		ID:      userUUID,
	}

	if err := s.queries.Enable2FA(ctx, params); err != nil {
		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return backupCodes, nil
}
