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

type IdmUser struct {
	UserUuid string                 `json:"user_uuid,omitempty"`
	Role     []string               `json:"role,omitempty"`
	Custom   map[string]interface{} `json:"custom,omitempty"`
}

func (s LoginService) Login(ctx context.Context, params LoginParams, password string) ([]IdmUser, error) {
	// Find user by username
	dbUsers, err := s.queries.FindUserByUsername(ctx, utils.ToNullString(params.Username))
	if err != nil || len(dbUsers) == 0 {
		return []IdmUser{}, fmt.Errorf("user not found: %w", err)
	}

	if len(dbUsers) > 1 {
		return []IdmUser{}, fmt.Errorf("multiple users found with username %s", params.Username)
	}

	// Verify password
	valid, err := CheckPasswordHash(password, string(dbUsers[0].Password))
	if err != nil {
		return []IdmUser{}, fmt.Errorf("error checking password: %w", err)
	}
	if !valid {
		return []IdmUser{}, fmt.Errorf("invalid password")
	}

	// Find user roles
	roles, err := s.FindUserRoles(ctx, dbUsers[0].Uuid)
	if err != nil {
		return []IdmUser{}, fmt.Errorf("error finding user roles: %w", err)
	}

	// Convert roles to string array
	validRoles := utils.GetValidStrings(roles)

	return []IdmUser{
		{
			UserUuid: dbUsers[0].Uuid.String(),
			Role:     validRoles,
			Custom:   make(map[string]interface{}),
		},
	}, nil
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
	users, err := s.queries.FindUserByUsername(ctx, utils.ToNullString(username))
	if err != nil || len(users) == 0 {
		slog.Warn("User not found", "err", err)
		return nil
	}
	if len(users) > 1 {
		slog.Warn("Unexpected: found multiple users")
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

	err = s.queries.InitPasswordResetToken(ctx, logindb.InitPasswordResetTokenParams{
		UserUuid: user.Uuid,
		Token:    resetToken,
		ExpireAt: expireAt,
	})
	if err != nil {
		slog.Error("Failed to save reset token", "err", err)
		return err
	}

	// Send reset email
	if user.Email == "" {
		slog.Info("User has no email address", "user", user)
		return err
	}
	err = s.SendPasswordResetEmail(ctx, user.Email, resetToken)
	if err != nil {
		return err
	}

	return nil
}
