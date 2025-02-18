package login

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slog"
)

type LoginService struct {
	queries             *logindb.Queries
	notificationManager *notification.NotificationManager
	userMapper          UserMapper
	delegatedUserMapper DelegatedUserMapper
}

func NewLoginService(queries *logindb.Queries, notificationManager *notification.NotificationManager, userMapper UserMapper, delegatedUserMapper DelegatedUserMapper) *LoginService {
	return &LoginService{
		queries:             queries,
		notificationManager: notificationManager,
		userMapper:          userMapper,
		delegatedUserMapper: delegatedUserMapper,
	}
}

type LoginParams struct {
	Email    string
	Username string
}

func (s LoginService) GetUsersByLoginUuid(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error) {
	return s.userMapper.GetUsers(ctx, loginUuid)
}

func (s LoginService) Login(ctx context.Context, params LoginParams, password string) ([]MappedUser, error) {
	// Find user by username
	loginUser, err := s.queries.FindLoginByUsername(ctx, utils.ToNullString(params.Username))
	if err != nil {
		if err == sql.ErrNoRows {
			return []MappedUser{}, fmt.Errorf("user not found")
		}
		return []MappedUser{}, fmt.Errorf("error finding user: %w", err)
	}

	// Verify password
	valid, err := CheckPasswordHash(password, string(loginUser.Password))
	if err != nil {
		return []MappedUser{}, fmt.Errorf("error checking password: %w", err)
	}
	if !valid {
		return []MappedUser{}, fmt.Errorf("invalid password")
	}

	users, err := s.userMapper.GetUsers(ctx, loginUser.Uuid)
	if err != nil {
		return []MappedUser{}, fmt.Errorf("error getting user roles: %w", err)
	}

	return users, nil
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

func (s LoginService) Create(ctx context.Context, params RegisterParam) (logindb.User, error) {
	slog.Debug("Registering user use params:", "params", params)
	// registerRequest := logindb.RegisterUserParams{}
	// copier.Copy(&registerRequest, params)
	// user, err := s.queries.RegisterUser(ctx, registerRequest)
	// if err != nil {
	// 	slog.Error("Failed to register user", "params", params, "err", err)
	// 	return logindb.User{}, err
	// }
	return logindb.User{}, nil
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
	resetPasswordParams := logindb.ResetPasswordParams{}
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
	err = s.queries.ResetPasswordByUuid(ctx, logindb.ResetPasswordByUuidParams{
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
	loginUser, err := s.queries.FindLoginByUsername(ctx, utils.ToNullString(username))
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Warn("User not found")
			return nil
		}
		slog.Error("Error finding user", "err", err)
		return err
	}

	// Get user info with roles
	userInfo, err := s.queries.FindUserInfoWithRoles(ctx, loginUser.Uuid)
	if err != nil {
		return fmt.Errorf("error finding user info: %w", err)
	}

	// Generate reset token
	resetToken := utils.GenerateRandomString(32)

	// Save token
	expireAt := pgtype.Timestamptz{}
	err = expireAt.Scan(time.Now().Add(24 * time.Hour))
	if err != nil {
		return fmt.Errorf("failed to create expiry time: %w", err)
	}

	err = s.queries.InitPasswordResetToken(ctx, logindb.InitPasswordResetTokenParams{
		UserUuid: loginUser.Uuid,
		Token:    resetToken,
		ExpireAt: expireAt,
	})
	if err != nil {
		slog.Error("Failed to save reset token", "err", err)
		return err
	}

	// Send reset email
	if userInfo.Email == "" {
		slog.Info("User has no email address", "user", userInfo)
		return err
	}
	err = s.SendPasswordResetEmail(ctx, userInfo.Email, resetToken)
	if err != nil {
		return err
	}

	return nil
}
