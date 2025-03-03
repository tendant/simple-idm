package login

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp/totp"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

type LoginService struct {
	queries             *logindb.Queries
	notificationManager *notification.NotificationManager
	userMapper          UserMapper
	delegatedUserMapper DelegatedUserMapper
	passwordManager     *PasswordManager
}

func NewLoginService(queries *logindb.Queries, notificationManager *notification.NotificationManager, userMapper UserMapper, delegatedUserMapper DelegatedUserMapper) *LoginService {
	// Create a password manager with default policy and current version
	passwordManager := NewPasswordManager(queries, nil, CurrentPasswordVersion)

	return &LoginService{
		queries:             queries,
		notificationManager: notificationManager,
		userMapper:          userMapper,
		delegatedUserMapper: delegatedUserMapper,
		passwordManager:     passwordManager,
	}
}

type LoginParams struct {
	Email    string
	Username string
}

type LoginResponse struct {
	Users   []MappedUser
	LoginId uuid.UUID
}

func (s LoginService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error) {
	return s.userMapper.GetUsers(ctx, loginID)
}

// CheckPasswordByLoginId verifies a password for a given login ID
// It returns true if the password is valid, false otherwise
func (s *LoginService) CheckPasswordByLoginId(ctx context.Context, loginId string, password, hashedPassword string) (bool, error) {
	// Get the password version
	parsedLoginId := utils.ParseUUID(loginId)
	passwordVersion, err := s.queries.GetUserPasswordVersion(ctx, parsedLoginId)
	if err != nil {
		// If there's an error getting the version, assume version 1
		slog.Warn("Could not get password version, assuming version 1", "error", err)
		passwordVersion = pgtype.Int4{Int32: 1, Valid: true}
	}

	// Verify password and upgrade if needed
	return s.passwordManager.AuthenticateAndUpgrade(
		ctx,
		loginId,
		password,
		hashedPassword,
		PasswordVersion(passwordVersion.Int32),
	)
}

func (s *LoginService) Login(ctx context.Context, username, password string) ([]MappedUser, error) {
	// Find user by username
	loginUser, err := s.queries.FindLoginByUsername(ctx, utils.ToNullString(username))
	if err != nil {
		if err == pgx.ErrNoRows {
			return []MappedUser{}, fmt.Errorf("invalid username or password")
		}
		return []MappedUser{}, fmt.Errorf("error finding user: %w", err)
	}

	// Verify password
	valid, err := s.CheckPasswordByLoginId(ctx, loginUser.ID.String(), password, string(loginUser.Password))
	if err != nil {
		return []MappedUser{}, fmt.Errorf("error checking password: %w", err)
	}

	if !valid {
		return []MappedUser{}, fmt.Errorf("invalid username or password")
	}

	// Get user info with roles
	users, err := s.userMapper.GetUsers(ctx, loginUser.ID)
	if err != nil {
		return []MappedUser{}, fmt.Errorf("error getting user roles: %w", err)
	}
	res := LoginResponse{
		Users:   users,
		LoginId: loginUser.ID,
	}

	return res.Users, nil
}

type RegisterParam struct {
	Email    string
	Name     string
	Password string
}

func (s LoginService) Verify2FACode(ctx context.Context, loginId string, code string) (bool, error) {
	// Get login's 2FA secret
	loginUuid, err := uuid.Parse(loginId)
	if err != nil {
		return false, fmt.Errorf("invalid login id: %w", err)
	}

	login, err := s.queries.GetLoginById(ctx, loginUuid)
	if err != nil {
		return false, fmt.Errorf("error getting login: %w", err)
	}

	// Check if 2FA is enabled
	if !login.TwoFactorEnabled.Bool {
		return false, fmt.Errorf("2FA is not enabled for this login")
	}

	// Get 2FA secret
	secret := login.TwoFactorSecret
	if !secret.Valid {
		return false, fmt.Errorf("2FA secret not found")
	}

	// Verify the code
	valid := totp.Validate(code, secret.String)
	if !valid {
		// Check backup codes
		isBackupValid, err := s.queries.ValidateBackupCode(ctx, logindb.ValidateBackupCodeParams{
			ID:   loginUuid,
			Code: code,
		})
		if err != nil || !isBackupValid {
			return false, fmt.Errorf("invalid 2FA code")
		}

		// Mark backup code as used by removing it from the array
		err = s.queries.MarkBackupCodeUsed(ctx, logindb.MarkBackupCodeUsedParams{
			ID:   loginUuid,
			Code: code,
		})
		if err != nil {
			slog.Error("Failed to mark backup code as used", "error", err)
		}
	}

	return true, nil
}

func (s LoginService) Create(ctx context.Context, params RegisterParam) (logindb.User, error) {
	slog.Debug("Registering user with params:", "params", params)

	// Validate password complexity
	if err := s.passwordManager.CheckPasswordComplexity(params.Password); err != nil {
		return logindb.User{}, fmt.Errorf("password does not meet complexity requirements: %w", err)
	}

	// Hash the password
	hashedPassword, err := s.passwordManager.HashPassword(params.Password)
	if err != nil {
		return logindb.User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	// Since we don't have a direct CreateUser method, we need to use what's available
	// This is a placeholder implementation - you'll need to implement the actual user creation
	// based on the available methods in your logindb package
	slog.Info("User creation not fully implemented", "email", params.Email)

	// Return a placeholder user with the provided information
	user := logindb.User{
		ID:             uuid.New(),
		Email:          params.Email,
		Name:           utils.ToNullString(params.Name),
		Password:       []byte(hashedPassword),
		CreatedAt:      time.Now(),
		LastModifiedAt: time.Now(),
	}

	return user, nil
}

func (s LoginService) HashPassword(password string) (string, error) {
	return s.passwordManager.HashPassword(password)
}

// CheckPasswordComplexity verifies that a password meets the complexity requirements
func (s LoginService) CheckPasswordComplexity(password string) error {
	return s.passwordManager.CheckPasswordComplexity(password)
}

func (s LoginService) CheckPasswordHash(password, hashedPassword string, version PasswordVersion) (bool, error) {
	return s.passwordManager.CheckPasswordHash(password, hashedPassword, version)
}

func (s LoginService) EmailVerify(ctx context.Context, param string) error {
	slog.Debug("Verifying user use params:", "params", param)
	// err := s.queries.EmailVerify(ctx, param)
	// if err != nil {
	// 	slog.Error("Failed to verify user", "params", param, "err", err)
	// 	return err
	// }
	return nil
}

func (s LoginService) ResetPasswordUsers(ctx context.Context, params PasswordReset) error {
	// Validate password complexity
	if err := s.passwordManager.CheckPasswordComplexity(params.Password); err != nil {
		return fmt.Errorf("password does not meet complexity requirements: %w", err)
	}

	// Hash the password
	hashedPassword, err := s.passwordManager.HashPassword(params.Password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create reset password parameters
	resetPasswordParams := logindb.ResetPasswordByIdParams{
		Password: []byte(hashedPassword),
		ID:       uuid.MustParse(params.Code), // Assuming Code is the ID of the user
	}

	slog.Debug("Resetting password", "params", params.Code)
	err = s.queries.ResetPasswordById(ctx, resetPasswordParams)
	if err != nil {
		return fmt.Errorf("failed to reset password: %w", err)
	}

	return nil
}

func (s LoginService) FindUserRoles(ctx context.Context, uuid uuid.UUID) ([]sql.NullString, error) {
	slog.Debug("FindUserRoles", "params", uuid)
	roles, err := s.queries.FindUserRolesByUserId(ctx, uuid)
	return roles, err
}

func (s LoginService) GetMe(ctx context.Context, userUuid uuid.UUID) (logindb.FindUserInfoWithRolesRow, error) {
	slog.Debug("GetMe", "userUuid", userUuid)
	userInfo, err := s.queries.FindUserInfoWithRoles(ctx, userUuid)
	if err != nil {
		slog.Error("Failed getting userinfo with roles", "err", err)
		return logindb.FindUserInfoWithRolesRow{}, err
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
	resetLink := fmt.Sprintf("%s/password-reset/%s", s.notificationManager.BaseUrl, resetToken)
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
	// Use the password manager to handle the reset
	return s.passwordManager.ResetPassword(ctx, token, newPassword)
}

// ChangePassword changes a user's password after verifying the current password
func (s LoginService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	// Delegate to the password manager
	return s.passwordManager.ChangePassword(ctx, userID, currentPassword, newPassword)
}

// InitPasswordReset generates a reset token and sends a reset email
func (s *LoginService) InitPasswordReset(ctx context.Context, username string) error {
	// Find user by username
	loginUser, err := s.queries.FindLoginByUsername(ctx, utils.ToNullString(username))
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Warn("User not found")
			return nil
		}
		slog.Error("Error finding user", "err", err)
		return err
	}

	// Get user info with roles
	users, err := s.userMapper.GetUsers(ctx, loginUser.ID)
	if err != nil || len(users) == 0 {
		return fmt.Errorf("error finding user info: %w", err)
	}

	// Generate reset token using password manager
	resetToken, err := s.passwordManager.InitPasswordReset(ctx, loginUser.ID.String())
	if err != nil {
		return err
	}

	// Send reset email
	if users[0].Email == "" {
		slog.Info("User has no email address", "user", users[0])
		return fmt.Errorf("user has no email address")
	}

	err = s.SendPasswordResetEmail(ctx, users[0].Email, resetToken)
	if err != nil {
		return err
	}

	return nil
}

func getUniqueEmailsFromUsers(mappedUsers []MappedUser) []DeliveryOption {
	// Use a map to track unique emails
	emailMap := make(map[string]struct{})

	// Collect emails from mapped users
	for _, mu := range mappedUsers {
		if email, ok := mu.ExtraClaims["email"].(string); ok && email != "" {
			emailMap[email] = struct{}{}
		}
	}

	// Convert map keys to slice
	options := make([]DeliveryOption, 0, len(emailMap))
	for email := range emailMap {
		options = append(options, DeliveryOption{
			HashedValue:  hashEmail(email),
			DisplayValue: maskEmail(email),
		})
	}

	return options
}

// hashEmail generates a SHA-256 hash of the email.
func hashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// maskEmail masks part of the email for display.
func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email // Return as is if it's not a valid email
	}
	localPart := parts[0]
	domain := parts[1]

	// Show first character and mask the rest, keeping the domain
	if len(localPart) > 1 {
		return localPart[:1] + "***@" + domain
	}
	return "***@" + domain
}
