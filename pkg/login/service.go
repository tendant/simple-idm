package login

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jinzhu/copier"
	"github.com/lib/pq"
	"github.com/tendant/simple-idm/pkg/login/db"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/utils"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slog"
)

type LoginService struct {
	queries             *db.Queries
	notificationManager *notification.NotificationManager
}

// Disable2FA disables 2FA for a user after verifying their password and 2FA code
func (s LoginService) Disable2FA(ctx context.Context, userUUID uuid.UUID, currentPassword string, code string) error {
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
func (s LoginService) Enable2FA(ctx context.Context, userUUID uuid.UUID, secret string, code string) ([]string, error) {
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
	params := db.Enable2FAParams{
		TwoFactorSecret:      pgtype.Text{String: secret, Valid: true},
		TwoFactorBackupCodes: pq.StringArray(backupCodes),
		Uuid:                 userUUID,  // Note: lowercase 'u' in Uuid
	}

	if err := s.queries.Enable2FA(ctx, params); err != nil {
		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return backupCodes, nil
}

func NewLoginService(queries *db.Queries, notificationManager *notification.NotificationManager) *LoginService {
	return &LoginService{
		queries:             queries,
		notificationManager: notificationManager,
	}
}

type LoginParams struct {
	Email    string
	Username string
}

type IdmUser struct {
	UserUuid string   `json:"user_uuid,omitempty"`
	Role     []string `json:"role,omitempty"`
}

func (s LoginService) Login(ctx context.Context, params LoginParams) ([]db.FindUserByUsernameRow, error) {
	user, err := s.queries.FindUserByUsername(ctx, utils.ToNullString(params.Username))
	return user, err
}

type RegisterParam struct {
	Email    string
	Name     string
	Password string
}

// HashPassword hashes the plain-text password using bcrypt.
func HashPassword(password string) (string, error) {
	if password == "" { // Null or empty password check
		return "", fmt.Errorf("password cannot be empty")
	}

	// Generate the bcrypt hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash compares the plain-text password with the stored hashed password.
func CheckPasswordHash(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" { // Null or empty checks
		return false, fmt.Errorf("password and hashed password cannot be empty")
	}

	// Compare the password with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s LoginService) Create(ctx context.Context, params RegisterParam) (db.User, error) {
	slog.Debug("Registering user use params:", "params", params)
	registerRequest := db.RegisterUserParams{}
	copier.Copy(&registerRequest, params)
	user, err := s.queries.RegisterUser(ctx, registerRequest)
	if err != nil {
		slog.Error("Failed to register user", "params", params, "err", err)
		return db.User{}, err
	}
	return user, err
}

func (s LoginService) EmailVerify(ctx context.Context, param string) error {
	slog.Debug("Verifying user use params:", "params", param)
	err := s.queries.EmailVerify(ctx, param)
	if err != nil {
		slog.Error("Failed to verify user", "params", param, "err", err)
		return err
	}
	return nil
}

func (s LoginService) ResetPasswordUsers(ctx context.Context, params PasswordReset) error {
	resetPasswordParams := db.ResetPasswordParams{}
	slog.Debug("resetPasswordParams", "params", params)
	copier.Copy(&resetPasswordParams, params)
	err := s.queries.ResetPassword(ctx, resetPasswordParams)
	return err
}

func (s LoginService) FindUserRoles(ctx context.Context, uuid uuid.UUID) ([]sql.NullString, error) {
	slog.Debug("FindUserRoles", "params", uuid)
	roles, err := s.queries.FindUserRolesByUserUuid(ctx, uuid)
	return roles, err
}

func (s LoginService) GetMe(ctx context.Context, userUuid uuid.UUID) (db.FindUserInfoWithRolesRow, error) {
	slog.Debug("GetMe", "userUuid", userUuid)
	userInfo, err := s.queries.FindUserInfoWithRoles(ctx, userUuid)
	if err != nil {
		slog.Error("Failed getting userinfo with roles", "err", err)
		return db.FindUserInfoWithRolesRow{}, err
	}
	return userInfo, err
}

func (s *LoginService) SendUsernameEmail(ctx context.Context, email string, username string) error {
	data := map[string]string{
		"Username": username,
	}
	return s.notificationManager.Send(notification.UsernameReminderNotice, notification.NotificationData{
		To:   email,
		Data: data,
	})
}

func (s *LoginService) SendPasswordResetEmail(ctx context.Context, email string, resetToken string) error {
	resetLink := fmt.Sprintf("https://example.com/reset-password?token=%s", resetToken)
	data := map[string]string{
		"Link": resetLink,
	}
	return s.notificationManager.Send(notice.PasswordResetInit, notification.NotificationData{
		To:   email,
		Data: data,
	})
}

// ResetPassword validates the reset token and updates the user's password
func (s *LoginService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate token and get user info
	tokenInfo, err := s.queries.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	err = s.queries.ResetPasswordByUuid(ctx, db.ResetPasswordByUuidParams{
		Password: hashedPassword,
		Uuid:     tokenInfo.UserUuid,
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	err = s.queries.MarkPasswordResetTokenUsed(ctx, token)
	if err != nil {
		slog.Error("Failed to mark token as used", "err", err)
		// Don't return error as password was successfully reset
	}

	return nil
}

// InitPasswordReset generates a reset token and sends a reset email
func (s *LoginService) InitPasswordReset(ctx context.Context, username string) error {
	// Find user by username
	users, err := s.queries.FindUserByUsername(ctx, utils.ToNullString(username))
	if err != nil || len(users) == 0 {
		return fmt.Errorf("user not found")
	}
	user := users[0]

	// Generate reset token
	resetToken := utils.GenerateRandomString(32)

	// Save token
	expireAt := pgtype.Timestamptz{}
	err = expireAt.Scan(time.Now().Add(24 * time.Hour))
	if err != nil {
		return fmt.Errorf("failed to create expiry time: %w", err)
	}

	err = s.queries.InitPasswordResetToken(ctx, db.InitPasswordResetTokenParams{
		UserUuid: user.Uuid,
		Token:    resetToken,
		ExpireAt: expireAt,
	})
	if err != nil {
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	// Send reset email
	if user.Email == "" {
		return fmt.Errorf("user has no email address")
	}
	err = s.SendPasswordResetEmail(ctx, user.Email, resetToken)
	if err != nil {
		return fmt.Errorf("failed to send reset email: %w", err)
	}

	return nil
}
