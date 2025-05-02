package login

import (
	"context"
	"fmt"
	"time"

	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/utils"
)

type LoginService struct {
	repository          LoginRepository
	notificationManager *notification.NotificationManager
	userMapper          mapper.UserMapper
	delegatedUserMapper mapper.DelegatedUserMapper
	passwordManager     *PasswordManager
	postPasswordUpdate  *PostPasswordUpdateFunc
	maxFailedAttempts   int
	lockoutDuration     time.Duration
}

// PostPasswordUpdateFunc is a function that will be called after a password update
// It receives the username and password that were updated
type PostPasswordUpdateFunc func(username string, password []byte) error

// LoginServiceOptions contains optional parameters for creating a LoginService
type LoginServiceOptions struct {
	PasswordManager *PasswordManager
}

// Option is a function that configures a LoginService
type Option func(*LoginService)

// WithNotificationManager sets the notification manager for the LoginService
func WithNotificationManager(notificationManager *notification.NotificationManager) Option {
	return func(ls *LoginService) {
		ls.notificationManager = notificationManager
	}
}

// WithUserMapper sets the user mapper for the LoginService
func WithUserMapper(userMapper mapper.UserMapper) Option {
	return func(ls *LoginService) {
		ls.userMapper = userMapper
	}
}

// WithDelegatedUserMapper sets the delegated user mapper for the LoginService
func WithDelegatedUserMapper(delegatedUserMapper mapper.DelegatedUserMapper) Option {
	return func(ls *LoginService) {
		ls.delegatedUserMapper = delegatedUserMapper
	}
}

// WithPasswordManager sets the password manager for the LoginService
func WithPasswordManager(passwordManager *PasswordManager) Option {
	return func(ls *LoginService) {
		ls.passwordManager = passwordManager
	}
}

// WithPostPasswordUpdate sets the post password update function for the LoginService
func WithPostPasswordUpdate(postPasswordUpdate *PostPasswordUpdateFunc) Option {
	return func(ls *LoginService) {
		ls.postPasswordUpdate = postPasswordUpdate
	}
}

// WithMaxFailedAttempts sets the maximum number of failed login attempts before locking an account
func WithMaxFailedAttempts(maxFailedAttempts int) Option {
	return func(ls *LoginService) {
		ls.maxFailedAttempts = maxFailedAttempts
	}
}

// WithLockoutDuration sets the duration for which an account is locked after exceeding max failed attempts
func WithLockoutDuration(lockoutDuration time.Duration) Option {
	return func(ls *LoginService) {
		ls.lockoutDuration = lockoutDuration
	}
}

// NewLoginService creates a new LoginService with the given options
func NewLoginService(
	repository LoginRepository,
	notificationManager *notification.NotificationManager,
	userMapper mapper.UserMapper,
	delegatedUserMapper mapper.DelegatedUserMapper,
	options *LoginServiceOptions,
	postPasswordUpdate *PostPasswordUpdateFunc,
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
		notificationManager: notificationManager,
		userMapper:          userMapper,
		delegatedUserMapper: delegatedUserMapper,
		passwordManager:     passwordManager,
		postPasswordUpdate:  postPasswordUpdate,
	}
}

// NewLoginServiceWithOptions creates a new LoginService with the given options
func NewLoginServiceWithOptions(repository LoginRepository, opts ...Option) *LoginService {
	// Create a default password manager
	passwordManager := NewPasswordManagerWithRepository(repository)

	// Create service with default values
	ls := &LoginService{
		repository:        repository,
		passwordManager:   passwordManager,
		maxFailedAttempts: 5,                // Default to 5 failed attempts
		lockoutDuration:   30 * time.Minute, // Default to 30 minute lockout
	}

	// Apply all options
	for _, opt := range opts {
		opt(ls)
	}

	return ls
}

type LoginParams struct {
	Email    string
	Username string
}

type LoginResponse struct {
	Users   []mapper.User
	LoginId uuid.UUID
}

type LoginResult struct {
	Users         []mapper.User
	LoginID       uuid.UUID
	Success       bool
	FailureReason string
	LockedUntil   time.Time
}

const (
	FAILURE_REASON_INTERNAL_ERROR        = "internal_error"
	FAILURE_REASON_ACCOUNT_LOCKED        = "account_locked"
	FAILURE_REASON_PASSWORD_EXPIRED      = "password_expired"
	FAILURE_REASON_INVALID_CREDENTIALS   = "invalid_credentials"
	FAILURE_REASON_NO_USER_FOUND         = "no_user_found"
	FAILURE_REASON_2FA_VALIDATION_FAILED = "2fa_validation_failed"
)

func (s LoginService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	// Get users from repository
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginID)
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

func (s *LoginService) FindLoginByUsername(ctx context.Context, username string) (LoginEntity, error) {
	usernameStr := username
	usernameValid := username != ""
	login, err := s.repository.FindLoginByUsername(ctx, usernameStr, usernameValid)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Error("no login found with username: %s", username)
			return LoginEntity{}, fmt.Errorf("invalid username or password")
		}
		slog.Error("error finding login with username: %s", username)
		return LoginEntity{}, fmt.Errorf("error finding user: %w", err)
	}
	return login, nil
}

func (s *LoginService) Login(ctx context.Context, username, password string) (LoginResult, error) {
	result := LoginResult{
		Success: false,
	}

	// Find user by username
	login, err := s.FindLoginByUsername(ctx, username)
	if err != nil {
		result.FailureReason = FAILURE_REASON_INTERNAL_ERROR
		return result, fmt.Errorf("error finding login: %w", err)
	}

	// Set the login ID in the result
	result.LoginID = login.ID

	// Check if account is locked
	isLocked, err := s.repository.IsAccountLocked(ctx, login.ID)
	if err != nil {
		slog.Error("Failed to check if account is locked", "err", err)
		result.FailureReason = FAILURE_REASON_INTERNAL_ERROR
		return result, err
	}

	if isLocked {
		// Get the locked until time
		_, _, lockedUntil, err := s.repository.GetFailedLoginAttempts(ctx, login.ID)
		if err != nil {
			slog.Error("Failed to get account lock details", "err", err)
			// If we can't get the lock details, use a default duration
			lockedUntil = time.Now().Add(s.lockoutDuration)
		}

		// Set failure information
		result.FailureReason = FAILURE_REASON_ACCOUNT_LOCKED
		result.LockedUntil = lockedUntil

		return result, &AccountLockedError{LoginID: login.ID, LockedUntil: lockedUntil}
	}

	// Verify password
	valid, err := s.CheckPasswordByLoginId(ctx, login.ID, password, string(login.Password))
	if err != nil {
		slog.Error("Failed to check password", "err", err)
		result.FailureReason = FAILURE_REASON_INTERNAL_ERROR
		return result, err
	}
	if !valid {
		slog.Error("invalid username or password from check password by login id")

		// Set failure information
		result.FailureReason = FAILURE_REASON_INVALID_CREDENTIALS

		// Increment failed login attempts counter
		_, _, err := s.IncrementFailedAttemptsAndCheckLock(ctx, login.ID)
		if err != nil {
			slog.Error("Failed to increment failed login attempts", "err", err)
		}

		return result, fmt.Errorf("invalid username or password")
	}

	// Check if password is expired
	isExpired, err := s.passwordManager.IsPasswordExpired(ctx, login.ID.String())
	if err != nil {
		slog.Error("Failed to check password expiration", "err", err)
		// Don't block login if we can't check expiration
	} else if isExpired {
		result.FailureReason = FAILURE_REASON_PASSWORD_EXPIRED
		return result, fmt.Errorf("password has expired and must be changed")
	}

	// Get users associated with this login ID using the UserRepository
	users, err := s.userMapper.FindUsersByLoginID(ctx, login.ID)
	if err != nil {
		slog.Error("error getting users by login ID", "err", err)
		result.FailureReason = FAILURE_REASON_INTERNAL_ERROR
		return result, fmt.Errorf("error getting user information: %w", err)
	}

	// If login is successful, reset failed login attempts
	err = s.repository.ResetFailedLoginAttempts(ctx, login.ID)
	if err != nil {
		slog.Error("Failed to reset failed login attempts", "err", err)
	}

	// Set success information
	result.Success = true
	result.Users = users

	return result, nil
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
	user, err := s.userMapper.GetUserByUserID(ctx, userID)
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
	user, err := s.userMapper.GetUserByUserID(ctx, userID)
	if err != nil {
		slog.Error("Failed getting user", "err", err)
		return UserInfo{}, err
	}

	// Convert User to UserInfo
	userInfo := UserInfo{
		Email:     user.UserInfo.Email,
		Name:      user.DisplayName,
		NameValid: user.DisplayName != "",
		Roles:     user.Roles,
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
	Username   string
}

func (s *LoginService) SendPasswordResetEmail(ctx context.Context, param SendPasswordResetEmailParams) error {
	resetLink := fmt.Sprintf("%s/auth/user/reset-password?token=%s", s.notificationManager.BaseUrl, param.ResetToken)
	slog.Info("Sending password reset email", "email", param.Email, "resetLink", resetLink)
	data := map[string]string{
		"Link":     resetLink,
		"UserId":   param.UserId,
		"Username": param.Username,
	}
	return s.notificationManager.Send(notice.PasswordResetInit, notification.NotificationData{
		To:   param.Email,
		Data: data,
	})
}

// ResetPassword validates the reset token and updates the user's password
func (s *LoginService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// first try to reset password in new login
	loginID, err := s.passwordManager.ResetPassword(ctx, token, newPassword)
	if err != nil {
		slog.Error("Failed to reset password", "err", err)
		return err
	}
	// if new login succeed, try to update in old login for backward-compatibility
	if s.postPasswordUpdate != nil {
		passwordBytes := []byte(newPassword)
		loginUuid, err := uuid.Parse(loginID)
		if err != nil {
			slog.Error("Failed to parse login ID", "err", err)
			return err
		}
		login, err := s.repository.GetLoginById(ctx, loginUuid)
		if err != nil {
			slog.Error("Failed to get login by ID", "err", err)
			return err
		}
		err = (*s.postPasswordUpdate)(login.Username, passwordBytes)
		if err != nil {
			slog.Error("Failed in post-password update", "err", err)
			return err
		}
	}
	return nil
}

// ChangePassword changes a user's password after verifying the current password
func (s LoginService) ChangePassword(ctx context.Context, loginID, currentPassword, newPassword string) error {
	// first try to change password in new login
	err := s.passwordManager.ChangePassword(ctx, loginID, currentPassword, newPassword)
	if err != nil {
		slog.Error("Failed to change password", "err", err)
		return err
	}
	// if new login succeed, try to update in old login for backward-compatibility
	if s.postPasswordUpdate != nil {
		passwordBytes := []byte(newPassword)
		loginUuid, err := uuid.Parse(loginID)
		if err != nil {
			slog.Error("Failed to parse login ID", "err", err)
			return err
		}
		login, err := s.repository.GetLoginById(ctx, loginUuid)
		if err != nil {
			slog.Error("Failed to get login by ID", "err", err)
			return err
		}
		err = (*s.postPasswordUpdate)(login.Username, passwordBytes)
		if err != nil {
			slog.Error("Failed in post-password update", "err", err)
			return err
		}
	}
	return nil
}

// InitPasswordReset generates a reset token and sends a reset email
func (s *LoginService) InitPasswordReset(ctx context.Context, username string) error {
	// Find user by username
	loginUser, err := s.FindLoginByUsername(ctx, username)
	if err != nil {
		return err
	}

	// Get user info with roles
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginUser.ID)
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
			UserId:     user.UserId,
			ResetToken: resetToken,
			Username:   username,
		})
		if err != nil {
			slog.Error("Error sending password reset email", "err", err, "user", user.UserId)
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

// ToTokenClaims converts a User to token claims using the UserMapper
func (s *LoginService) ToTokenClaims(user mapper.User) (rootModifications map[string]interface{}, extraClaims map[string]interface{}) {
	if s.userMapper == nil {
		slog.Warn("UserMapper is nil, returning empty claims")
		return map[string]interface{}{}, map[string]interface{}{}
	}
	return s.userMapper.ToTokenClaims(user)
}

// IsPasswordExpired checks if a password is expired or about to expire
func (s *LoginService) IsPasswordExpired(ctx context.Context, loginID string) (bool, int, error) {
	return s.passwordManager.GetPasswordExpirationInfo(ctx, loginID)
}

// FindUsernameByEmail finds a username by email address
func (s *LoginService) FindUsernameByEmail(ctx context.Context, email string) (string, bool, error) {
	// Use the UserRepository to find usernames by email
	usernames, err := s.userMapper.FindUsernamesByEmail(ctx, email)
	if err != nil {
		slog.Error("Failed to find usernames by email", "err", err)
		return "", false, err
	}

	// If no usernames found, return empty with false flag
	if len(usernames) == 0 {
		slog.Info("No usernames found for email", "email", email)
		return "", false, nil
	}
	slog.Info("Usernames found for email", "email", email, "usernames", usernames)

	// Return the first username found
	return usernames[0], true, nil
}

// RecordLoginAttempt records a login attempt
func (s *LoginService) RecordLoginAttempt(ctx context.Context, loginID uuid.UUID, ipAddress, userAgent, deviceFingerprint string, success bool, failureReason string) error {
	return s.repository.RecordLoginAttempt(ctx, LoginAttempt{
		LoginID:           loginID,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
		Success:           success,
		FailureReason:     failureReason,
	})
}

// IncrementFailedAttemptsAndCheckLock increments the failed login attempts counter
// and checks if the account should be locked. Returns true if the account is now locked,
// along with the lock duration if applicable.
func (s *LoginService) IncrementFailedAttemptsAndCheckLock(ctx context.Context, loginID uuid.UUID) (bool, time.Duration, error) {
	// Increment failed login attempts counter
	err := s.repository.IncrementFailedLoginAttempts(ctx, loginID)
	if err != nil {
		slog.Error("Failed to increment failed login attempts", "err", err)
		return false, 0, err
	}

	// Check if account should be locked (max failed attempts)
	failedAttempts, _, _, err := s.repository.GetFailedLoginAttempts(ctx, loginID)
	if err != nil {
		slog.Error("Failed to get failed login attempts", "err", err)
		return false, 0, err
	}

	if failedAttempts >= int32(s.maxFailedAttempts) {
		// Lock the account
		err = s.repository.LockAccount(ctx, loginID, s.lockoutDuration)
		if err != nil {
			slog.Error("Failed to lock account", "err", err)
			return false, 0, err
		}
		slog.Info("Account locked due to too many failed login attempts", "loginID", loginID)
		return true, s.lockoutDuration, nil
	}

	return false, 0, nil
}

// AccountLockedError represents an error when an account is locked due to too many failed login attempts
type AccountLockedError struct {
	LoginID     uuid.UUID
	LockedUntil time.Time
}

func (e *AccountLockedError) Error() string {
	return fmt.Sprintf("account is locked due to too many failed login attempts until %s", e.LockedUntil.Format(time.RFC3339))
}

// IsAccountLockedError checks if an error is an AccountLockedError
func IsAccountLockedError(err error) bool {
	_, ok := err.(*AccountLockedError)
	return ok
}

// GetLockedUntil returns the time until which the account is locked
func GetLockedUntil(err error) (time.Time, bool) {
	if accErr, ok := err.(*AccountLockedError); ok {
		return accErr.LockedUntil, true
	}
	return time.Time{}, false
}

// Helper functions for extracting information from context
func getIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value("ip").(string); ok {
		return ip
	}
	return ""
}

func getUserAgentFromContext(ctx context.Context) string {
	if ua, ok := ctx.Value("user_agent").(string); ok {
		return ua
	}
	return ""
}

func getDeviceFingerprintFromContext(ctx context.Context) string {
	if fp, ok := ctx.Value("device_fingerprint").(string); ok {
		return fp
	}
	return ""
}
