package profile

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
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
		ID:       user.LoginID.UUID,
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
	err := s.loginService.ChangePassword(
		ctx,
		params.UserUuid.String(),
		params.CurrentPassword,
		params.NewPassword,
	)
	if err != nil {
		slog.Error("Failed to change password", "uuid", params.UserUuid, "err", err)
		return err
	}
	return nil
}

func (s *ProfileService) GetPasswordPolicy() *login.PasswordPolicy {
	return s.loginService.GetPasswordPolicy()
}

// Disable2FA disables 2FA for a user after verifying their password and 2FA code
// func (s ProfileService) Disable2FA(ctx context.Context, userUUID uuid.UUID, currentPassword string, code string) error {
// 	// Get the user to verify password
// 	user, err := s.queries.FindUserByUsername(ctx, utils.ToNullString(userUUID.String()))
// 	if err != nil || len(user) == 0 {
// 		return fmt.Errorf("user not found")
// 	}

// 	// TODO: Verify password using bcrypt
// 	// TODO: Verify 2FA code using current secret

// 	// Disable 2FA
// 	return s.queries.Disable2FA(ctx, userUUID)
// }

// Enable2FA enables 2FA for a user and generates backup codes
// func (s ProfileService) Enable2FA(ctx context.Context, userUUID uuid.UUID, secret string, code string) ([]string, error) {
// 	// Verify the code is valid for the secret
// 	totp := gotp.NewDefaultTOTP(secret)
// 	if !totp.Verify(code, time.Now().Unix()) {
// 		return nil, fmt.Errorf("invalid 2FA code")
// 	}

// 	// Generate backup codes (8 random codes)
// 	backupCodes := make([]string, 8)
// 	for i := range backupCodes {
// 		bytes := make([]byte, 4)
// 		if _, err := rand.Read(bytes); err != nil {
// 			return nil, fmt.Errorf("failed to generate backup codes: %w", err)
// 		}
// 		backupCodes[i] = hex.EncodeToString(bytes)
// 	}

// 	// Enable 2FA in database
// 	params := profiledb.Enable2FAParams{
// 		Column1: secret,
// 		Column2: backupCodes,
// 		ID:      userUUID,
// 	}

// 	if err := s.queries.Enable2FA(ctx, params); err != nil {
// 		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
// 	}

// 	return backupCodes, nil
// }
