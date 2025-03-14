package login

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

type LoginService struct {
	repository          LoginRepository
	userRepository      UserRepository
	notificationManager *notification.NotificationManager
	userMapper          mapper.UserMapper
	delegatedUserMapper mapper.DelegatedUserMapper
	passwordManager     *PasswordManager
}

// LoginServiceOptions contains optional parameters for creating a LoginService
type LoginServiceOptions struct {
	PasswordManager *PasswordManager
}

func NewLoginService(
	repository LoginRepository,
	userRepository UserRepository,
	notificationManager *notification.NotificationManager,
	userMapper mapper.UserMapper,
	delegatedUserMapper mapper.DelegatedUserMapper,
	options *LoginServiceOptions,
) *LoginService {
	var passwordManager *PasswordManager
	// Use provided password manager if available
	if options != nil && options.PasswordManager != nil {
		passwordManager = options.PasswordManager
	} else {
		// Create a new password manager that uses the repository
		passwordManager = NewPasswordManagerWithRepository(repository)
	}

	return &LoginService{
		repository:          repository,
		userRepository:      userRepository,
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
	Users   []mapper.User
	LoginId uuid.UUID
}

func (s LoginService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	// Get users from repository
	users, err := s.userRepository.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		slog.Error("Failed to find users by login ID", "err", err)
		return nil, err
	}

	// Return the users directly
	return users, nil
}

// CheckPasswordByLoginId verifies a password for a given login ID
// It returns true if the password is valid, false otherwise
func (s *LoginService) CheckPasswordByLoginId(ctx context.Context, loginId uuid.UUID, password, hashedPassword string) (bool, error) {
	// Get the password version
	parsedLoginId := loginId
	version, isValid, err := s.repository.GetPasswordVersion(ctx, parsedLoginId)
	if err != nil || !isValid {
		// If there's an error getting the version or it's not valid, assume version 1
		slog.Warn("Could not get password version, assuming version 1", "error", err)
		version = 1
	}

	// Verify password and upgrade if needed
	return s.passwordManager.AuthenticateAndUpgrade(
		ctx,
		loginId,
		password,
		hashedPassword,
		PasswordVersion(version),
	)
}

func (s *LoginService) Login(ctx context.Context, username, password string) ([]mapper.User, error) {
	// Find user by username
	usernameStr := username
	usernameValid := username != ""
	loginUser, err := s.repository.FindLoginByUsername(ctx, usernameStr, usernameValid)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Error("no login found with username: %s", username)
			return []mapper.User{}, fmt.Errorf("invalid username or password")
		}
		slog.Error("error finding login with username: %s", username)
		return []mapper.User{}, fmt.Errorf("error finding user: %w", err)
	}

	// Verify password
	valid, err := s.CheckPasswordByLoginId(ctx, loginUser.ID, password, string(loginUser.Password))
	if err != nil {
		slog.Error("error checking password: %w", err)
		return []mapper.User{}, fmt.Errorf("error checking password: %w", err)
	}

	if !valid {
		slog.Error("invalid username or password from check password by login id")
		return []mapper.User{}, fmt.Errorf("invalid username or password")
	}

	// Get users associated with this login ID using the UserRepository
	users, err := s.userRepository.FindUsersByLoginID(ctx, loginUser.ID)
	if err != nil {
		slog.Error("error getting users by login ID", "err", err)
		return []mapper.User{}, fmt.Errorf("error getting user information: %w", err)
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

	_, err = s.repository.GetLoginById(ctx, loginUuid)
	if err != nil {
		return false, fmt.Errorf("error getting login: %w", err)
	}

	// Get 2FA information from a separate table
	// Since we don't have direct access to the 2FA fields in the login table anymore
	// We'll need to handle this differently
	// For now, we'll assume 2FA is not enabled
	return false, fmt.Errorf("2FA functionality has been removed or restructured")

	// Since 2FA functionality has been removed or restructured,
	// we're returning early with an error message
	// The code below is kept as a reference but won't be executed
	/*
		// Verify the code
		valid := totp.Validate(code, secret.String)
		if !valid {
			// Check backup codes
			isBackupValid, err := s.queries.ValidateBackupCode(ctx)
			if err != nil || !isBackupValid {
				return false, fmt.Errorf("invalid 2FA code")
			}

			// Mark backup code as used
			err = s.queries.MarkBackupCodeUsed(ctx)
			if err != nil {
				slog.Error("Failed to mark backup code as used", "error", err)
			}
		}
	*/

	// return true, nil
}

func (s LoginService) Create(ctx context.Context, params RegisterParam) (logindb.User, error) {
	slog.Debug("Registering user with params:", "params", params)

	// Validate password complexity
	if err := s.passwordManager.CheckPasswordComplexity(params.Password); err != nil {
		return logindb.User{}, fmt.Errorf("password does not meet complexity requirements: %w", err)
	}

	// Hash the password
	_, err := s.passwordManager.HashPassword(params.Password)
	if err != nil {
		return logindb.User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	// Since we don't have a direct CreateUser method, we need to use what's available
	// This is a placeholder implementation - you'll need to implement the actual user creation
	// based on the available methods in your logindb package
	slog.Info("User creation not fully implemented", "email", params.Email)

	// Return a placeholder user with the provided information
	user := logindb.User{
		ID:    uuid.New(),
		Email: params.Email,
		Name:  utils.ToNullString(params.Name),
		// Password field removed as it's not in the User struct
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

func (s LoginService) FindUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	slog.Debug("FindUserRoles", "params", userID)
	// Get the user first to extract roles
	user, err := s.userRepository.GetUserByUserID(ctx, userID)
	if err != nil {
		slog.Error("Failed to get user", "err", err)
		return nil, err
	}

	// Extract roles from user's Extraclaims
	roles := []string{}
	if roleVal, ok := user.ExtraClaims["role"]; ok {
		if roleStr, ok := roleVal.(string); ok {
			roles = append(roles, roleStr)
		} else if roleArr, ok := roleVal.([]string); ok {
			roles = roleArr
		}
	}

	return roles, nil
}

func (s LoginService) GetMe(ctx context.Context, userID uuid.UUID) (UserInfo, error) {
	slog.Debug("GetMe", "userID", userID)
	// Get the user from the repository
	user, err := s.userRepository.GetUserByUserID(ctx, userID)
	if err != nil {
		slog.Error("Failed getting user", "err", err)
		return UserInfo{}, err
	}

	// Convert User to UserInfo
	userInfo := UserInfo{
		Email:     user.UserInfo.Email,
		Name:      user.UserInfo.Name,
		NameValid: user.UserInfo.Name != "",
		Roles:     s.extractRolesFromUser(user),
	}

	return userInfo, nil
}

// Helper method to extract roles from User object
func (s LoginService) extractRolesFromUser(user mapper.User) []string {
	roles := []string{}
	if roleVal, ok := user.ExtraClaims["role"]; ok {
		if roleStr, ok := roleVal.(string); ok {
			roles = append(roles, roleStr)
		} else if roleArr, ok := roleVal.([]string); ok {
			roles = roleArr
		}
	}
	return roles
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

type SendPasswordResetEmailParams struct {
	Email      string
	UserId     string
	ResetToken string
}

func (s *LoginService) SendPasswordResetEmail(ctx context.Context, param SendPasswordResetEmailParams) error {
	resetLink := fmt.Sprintf("%s/password-reset/%s", s.notificationManager.BaseUrl, param.ResetToken)
	data := map[string]string{
		"Link":   resetLink,
		"UserId": param.UserId,
	}
	return s.notificationManager.Send(notice.PasswordResetInit, notification.NotificationData{
		To:   param.Email,
		Data: data,
	})
}

// ResetPassword validates the reset token and updates the user's password
func (s *LoginService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Use the password manager to handle the reset
	return s.passwordManager.ResetPassword(ctx, token, newPassword)
}

// ChangePassword changes a user's password after verifying the current password
func (s LoginService) ChangePassword(ctx context.Context, loginID, currentPassword, newPassword string) error {
	// Delegate to the password manager
	return s.passwordManager.ChangePassword(ctx, loginID, currentPassword, newPassword)
}

// InitPasswordReset generates a reset token and sends a reset email
func (s *LoginService) InitPasswordReset(ctx context.Context, username string) error {
	// Find user by username
	usernameValid := username != ""
	loginUser, err := s.repository.FindLoginByUsername(ctx, username, usernameValid)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Warn("User not found")
			return nil
		}
		slog.Error("Error finding user", "err", err)
		return err
	}

	// Get user info with roles
	users, err := s.userRepository.FindUsersByLoginID(ctx, loginUser.ID)
	if err != nil || len(users) == 0 {
		return fmt.Errorf("error finding user info: %w", err)
	}

	// Generate reset token using password manager
	resetToken, err := s.passwordManager.InitPasswordReset(ctx, loginUser.ID)
	if err != nil {
		return err
	}

	// Track emails that have already been sent to
	sentEmails := make(map[string]bool)

	// Send password reset email to each user
	for _, user := range users {
		if user.UserInfo.Email == "" {
			continue
		}

		// Skip if we've already sent to this email
		if sentEmails[user.UserInfo.Email] {
			continue
		}

		err = s.SendPasswordResetEmail(ctx, SendPasswordResetEmailParams{
			Email:      user.UserInfo.Email,
			UserId:     user.UserID,
			ResetToken: resetToken,
		})
		if err != nil {
			slog.Error("Error sending password reset email", "err", err, "user", user.UserID)
		}

		// Mark this email as sent
		sentEmails[user.UserInfo.Email] = true
	}

	return nil
}

func getUniqueEmailsFromUsers(users []mapper.User) []MessageDeliveryOption {
	// Use a map to track unique emails
	emailMap := make(map[string]struct{})

	// Collect emails from users
	for _, user := range users {
		// Get email from UserInfo
		if user.UserInfo.Email != "" {
			emailMap[user.UserInfo.Email] = struct{}{}
		}
	}

	// Convert map keys to slice
	options := make([]MessageDeliveryOption, 0, len(emailMap))
	for email := range emailMap {
		options = append(options, MessageDeliveryOption{
			HashedValue:  utils.HashEmail(email),
			DisplayValue: utils.MaskEmail(email),
		})
	}

	return options
}

// GetPasswordPolicy returns the current password policy
func (s *LoginService) GetPasswordPolicy() *PasswordPolicy {
	return s.passwordManager.GetPolicy()
}

// GetRepository returns the login repository
func (s *LoginService) GetRepository() LoginRepository {
	return s.repository
}

// GetPasswordManager returns the password manager
func (s *LoginService) GetPasswordManager() *PasswordManager {
	return s.passwordManager
}

// FindUsernameByEmail finds a username by email address
func (s *LoginService) FindUsernameByEmail(ctx context.Context, email string) (string, bool, error) {
	// Use the UserRepository to find usernames by email
	usernames, err := s.userRepository.FindUsernamesByEmail(ctx, email)
	if err != nil {
		slog.Error("Failed to find usernames by email", "err", err)
		return "", false, err
	}

	// If no usernames found, return empty with false flag
	if len(usernames) == 0 {
		return "", false, nil
	}

	// Return the first username found
	return usernames[0], true, nil
}
