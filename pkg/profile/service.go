package profile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

type (
	Profile struct {
		ID             uuid.UUID `json:"id"`
		Email          string    `json:"email"`
		CreatedAt      time.Time `json:"created_at"`
		LastModifiedAt time.Time `json:"last_modified_at"`
		LoginID        uuid.UUID `json:"login_id"`
		Username       string    `json:"username"`
		Password       []byte    `json:"password"`
	}

	LoginRecord struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
	}

	FindUserByUsername struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
	}

	UpdateUsernameParam struct {
		ID       uuid.UUID `json:"id"`
		Username string    `json:"username"`
	}
	UpdateLoginIdParam struct {
		ID      uuid.UUID     `json:"id"`
		LoginID uuid.NullUUID `json:"login_id"`
	}
)

// ProfileRepository defines the interface for profile database operations
type ProfileRepository interface {
	// GetUserById retrieves a user by their ID
	GetUserById(ctx context.Context, id uuid.UUID) (Profile, error)
	// GetLoginById retrieves a login by its ID
	GetLoginById(ctx context.Context, id uuid.UUID) (LoginRecord, error)
	// FindUserByUsername finds users by their username
	FindUserByUsername(ctx context.Context, username string) ([]Profile, error)
	// UpdateUsername updates a user's username
	UpdateUsername(ctx context.Context, arg UpdateUsernameParam) error
	// UpdateLoginId updates a user's login ID
	UpdateLoginId(ctx context.Context, arg UpdateLoginIdParam) (uuid.UUID, error)
	// Additional methods can be added as needed
}

// PostgresProfileRepository implements ProfileRepository using profiledb.Queries
type PostgresProfileRepository struct {
	queries *profiledb.Queries
}

// NewPostgresProfileRepository creates a new PostgresProfileRepository
func NewPostgresProfileRepository(queries *profiledb.Queries) *PostgresProfileRepository {
	return &PostgresProfileRepository{
		queries: queries,
	}
}

// GetUserById implements ProfileRepository.GetUserById
func (r *PostgresProfileRepository) GetUserById(ctx context.Context, id uuid.UUID) (Profile, error) {
	var res Profile
	row, err := r.queries.GetUserById(ctx, id)
	if err != nil {
		slog.Error("Failed to get user", "err", err)
		return res, fmt.Errorf("failed to get user: %w", err)
	}

	res.ID = row.ID
	res.Email = row.Email
	res.CreatedAt = row.CreatedAt
	res.LastModifiedAt = row.LastModifiedAt
	res.LoginID = row.LoginID.UUID
	res.Username = row.Username.String

	return res, nil
}

func (r *PostgresProfileRepository) GetLoginById(ctx context.Context, id uuid.UUID) (LoginRecord, error) {
	var res LoginRecord
	row, err := r.queries.GetLoginById(ctx, id)
	if err != nil {
		slog.Error("Failed to get login", "err", err)
		return res, fmt.Errorf("failed to get login: %w", err)
	}

	res.ID = row.ID
	res.Username = row.Username.String

	return res, nil
}

// FindUserByUsername implements ProfileRepository.FindUserByUsername
func (r *PostgresProfileRepository) FindUserByUsername(ctx context.Context, username string) ([]Profile, error) {
	rows, err := r.queries.FindUserByUsername(ctx, utils.ToNullString(username))
	if err != nil {
		slog.Error("Failed to find user", "err", err)
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	var res []Profile
	for _, row := range rows {
		res = append(res, Profile{
			ID:       row.ID,
			Username: row.Username.String,
		})
	}
	return res, nil
}

// UpdateUsername implements ProfileRepository.UpdateUsername
func (r *PostgresProfileRepository) UpdateUsername(ctx context.Context, arg UpdateUsernameParam) error {
	err := r.queries.UpdateUsername(ctx, profiledb.UpdateUsernameParams{
		ID:       arg.ID,
		Username: utils.ToNullString(arg.Username),
	})
	if err != nil {
		slog.Error("Failed to update username", "err", err)
		return fmt.Errorf("failed to update username: %w", err)
	}
	return nil
}

func (r *PostgresProfileRepository) UpdateLoginId(ctx context.Context, arg UpdateLoginIdParam) (uuid.UUID, error) {
	login_id, err := r.queries.UpdateUserLoginId(ctx, profiledb.UpdateUserLoginIdParams{
		ID:      arg.ID,
		LoginID: arg.LoginID,
	})
	if err != nil {
		slog.Error("Failed to update login id", "err", err)
		return uuid.Nil, fmt.Errorf("failed to update login id: %w", err)
	}
	return login_id.UUID, nil
}

// ProfileService provides profile-related operations
type ProfileService struct {
	repository          ProfileRepository
	userMapper          mapper.UserMapper
	passwordManager     *login.PasswordManager
	notificationManager *notification.NotificationManager
}

// Option is a function that configures a ProfileService
type Option func(*ProfileService)

// WithUserMapper sets the user mapper for the ProfileService
func WithUserMapper(userMapper mapper.UserMapper) Option {
	return func(ps *ProfileService) {
		ps.userMapper = userMapper
	}
}

// WithPasswordManager sets the password manager for the ProfileService
func WithPasswordManager(passwordManager *login.PasswordManager) Option {
	return func(ps *ProfileService) {
		ps.passwordManager = passwordManager
	}
}

// WithNotificationManager sets the notification manager for the ProfileService
func WithNotificationManager(notificationManager *notification.NotificationManager) Option {
	return func(ps *ProfileService) {
		ps.notificationManager = notificationManager
	}
}

// NewProfileService creates a new ProfileService (legacy constructor)
func NewProfileService(repository ProfileRepository, passwordManager *login.PasswordManager, userMapper mapper.UserMapper, notificationManager *notification.NotificationManager) *ProfileService {
	return &ProfileService{
		repository:          repository,
		passwordManager:     passwordManager,
		userMapper:          userMapper,
		notificationManager: notificationManager,
	}
}

// NewProfileServiceWithOptions creates a new ProfileService with the given options
func NewProfileServiceWithOptions(repository ProfileRepository, opts ...Option) *ProfileService {
	// Create service with default values
	ps := &ProfileService{
		repository: repository,
	}

	// Apply all options
	for _, opt := range opts {
		opt(ps)
	}

	return ps
}

type UpdateUsernameParams struct {
	LoginID         uuid.UUID
	CurrentPassword string
	NewUsername     string
}

// UpdateUsername updates a user's username after verifying their password
func (s *ProfileService) UpdateUsername(ctx context.Context, params UpdateUsernameParams) error {
	// Check if the new username is already taken
	existingUsers, err := s.repository.FindUserByUsername(ctx, params.NewUsername)
	if err != nil {
		slog.Error("Failed to check username availability", "err", err)
		return fmt.Errorf("internal error")
	}
	if len(existingUsers) > 0 {
		return fmt.Errorf("username already taken")
	}

	// Update the username
	err = s.repository.UpdateUsername(ctx, UpdateUsernameParam{
		ID:       params.LoginID,
		Username: params.NewUsername,
	})
	if err != nil {
		slog.Error("Failed to update username", "uuid", params.LoginID, "err", err)
		return fmt.Errorf("failed to update username")
	}

	return nil
}

type UpdatePasswordParams struct {
	LoginID         uuid.UUID
	CurrentPassword string
	NewPassword     string
}

// UpdatePassword updates a user's password after verifying their current password
func (s *ProfileService) UpdatePassword(ctx context.Context, params UpdatePasswordParams) error {
	err := s.passwordManager.ChangePassword(
		ctx,
		params.LoginID.String(),
		params.CurrentPassword,
		params.NewPassword,
	)
	if err != nil {
		slog.Error("Failed to change password", "uuid", params.LoginID, "err", err)
		return err
	}

	// Send notification about password change
	if s.notificationManager != nil {
		err = s.SendPasswordChangeNotice(ctx, SendPasswordChangeNoticeParams{
			LoginID: params.LoginID,
		})
		if err != nil {
			// Log the error but don't fail the password change
			slog.Error("Failed to send password change notification", "err", err)
		}
	}

	return nil
}

func (s *ProfileService) GetPasswordPolicy() *login.PasswordPolicy {
	return s.passwordManager.GetPolicy()
}

func (s *ProfileService) UpdateLoginId(ctx context.Context, arg UpdateLoginIdParam) (uuid.UUID, error) {
	return s.repository.UpdateLoginId(ctx, arg)
}

// ToTokenClaims converts a User to token claims using the UserMapper
func (s *ProfileService) ToTokenClaims(user mapper.User) (rootModifications map[string]interface{}, extraClaims map[string]interface{}) {
	if s.userMapper == nil {
		slog.Warn("UserMapper is nil, returning empty claims")
		return map[string]interface{}{}, map[string]interface{}{}
	}
	return s.userMapper.ToTokenClaims(user)
}

func (s *ProfileService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	// Get users from repository
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		slog.Error("Failed to find users by login ID", "err", err)
		return nil, err
	}

	// Return the users directly
	return users, nil
}

func (s *ProfileService) GetLoginById(ctx context.Context, id uuid.UUID) (LoginRecord, error) {
	return s.repository.GetLoginById(ctx, id)
}

// SendPasswordChangeNoticeParams contains parameters for sending a password change notification
type SendPasswordChangeNoticeParams struct {
	LoginID uuid.UUID
}

// SendPasswordChangeNotice sends a notification when a user successfully changes their password
func (s *ProfileService) SendPasswordChangeNotice(ctx context.Context, params SendPasswordChangeNoticeParams) error {
	if s.notificationManager == nil {
		return errors.New("notification manager is not configured")
	}

	slog.Info("Sending password change notification", "loginID", params.LoginID)

	// Get current timestamp
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Prepare data for the template
	data := map[string]string{
		"login_id":  params.LoginID.String(),
		"timestamp": timestamp,
	}

	// Send the notification
	return s.notificationManager.Send(notification.PasswordResetNotice, notification.NotificationData{
		Data: data,
	})
}

// Disable2FA disables 2FA for a user after verifying their password and 2FA code
// func (s ProfileService) Disable2FA(ctx context.Context, userUUID uuid.UUID, currentPassword string, code string) error {
// 	// Get the user to verify password
// 	user, err := s.repository.FindUserByUsername(ctx, utils.ToNullString(userUUID.String()))
// 	if err != nil || len(user) == 0 {
// 		return fmt.Errorf("user not found")
// 	}

// 	// TODO: Verify password using bcrypt
// 	// TODO: Verify 2FA code using current secret

// 	// Disable 2FA
// 	return s.repository.Disable2FA(ctx, userUUID)
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

// 	if err := s.repository.Enable2FA(ctx, params); err != nil {
// 		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
// 	}

// 	return backupCodes, nil
// }
