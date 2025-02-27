package login

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jinzhu/copier"
	"github.com/pquerna/otp/totp"
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
	passwordManager     *PasswordManager
}

func NewLoginService(queries *logindb.Queries, notificationManager *notification.NotificationManager, userMapper UserMapper, delegatedUserMapper DelegatedUserMapper) *LoginService {
	// Create a password manager with default policy
	passwordManager := NewPasswordManager(queries, nil)
	
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

func (s LoginService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error) {
	return s.userMapper.GetUsers(ctx, loginID)
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

	// Verify password and upgrade if needed
	valid, err := s.passwordManager.AuthenticateAndUpgrade(ctx, loginUser.ID.String(), password, string(loginUser.Password))
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

	return users, nil
}

type RegisterParam struct {
	Email    string
	Name     string
	Password string
}

// HashPassword hashes the plain-text password using bcrypt.
func (s LoginService) HashPassword(password string) (string, error) {
	return s.passwordManager.HashPassword(password)
}

// CheckPasswordHash compares the plain-text password with the stored hashed password.
func (s LoginService) CheckPasswordHash(password, hashedPassword string) (bool, error) {
	return s.passwordManager.CheckPasswordHash(password, hashedPassword)
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
	
	// Here you would create the user with the hashed password
	// This is commented out as it appears to be in the original code
	// registerRequest := logindb.RegisterUserParams{
	//    Name: params.Name,
	//    Email: params.Email,
	//    Password: []byte(hashedPassword),
	// }
	// user, err := s.queries.RegisterUser(ctx, registerRequest)
	// if err != nil {
	//    slog.Error("Failed to register user", "params", params, "err", err)
	//    return logindb.User{}, err
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
	resetPasswordParams := logindb.ResetPasswordParams{
		Code:     params.Code,
		Password: []byte(hashedPassword),
	}
	
	slog.Debug("Resetting password", "params", params.Code)
	err = s.queries.ResetPassword(ctx, resetPasswordParams)
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
