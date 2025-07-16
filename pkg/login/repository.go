package login

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/login/logindb"
)

// Domain models for the login repository

// LoginEntity represents a user login record in the domain model
type LoginEntity struct {
	ID                  uuid.UUID
	Username            string
	UsernameValid       bool
	Password            []byte
	PasswordVersion     int32
	CreatedAt           time.Time
	UpdatedAt           time.Time
	FailedLoginAttempts int32
	LastFailedAttemptAt time.Time
	LockedUntil         time.Time
	PasswordUpdatedAt   time.Time
	PasswordExpiresAt   time.Time
	IsPasswordless      bool // New field for passwordless login
}

// MagicLinkToken represents a magic link token for passwordless login
type MagicLinkToken struct {
	ID        uuid.UUID
	LoginID   uuid.UUID
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time // Pointer to allow nil for unused tokens
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID      uuid.UUID
	LoginID uuid.UUID
}

// UserInfo represents user information with roles
type UserInfo struct {
	Email     string
	Name      string
	NameValid bool
	Roles     []string
}

// UserWithRoles represents a user with their roles
type UserWithRoles struct {
	ID             uuid.UUID
	Name           string
	NameValid      bool
	Email          string
	CreatedAt      time.Time
	LastModifiedAt time.Time
	Roles          []string
}

// PasswordHistoryEntry represents a password history entry
type PasswordHistoryEntry struct {
	ID              uuid.UUID
	LoginID         uuid.UUID
	PasswordHash    []byte
	PasswordVersion int32
	CreatedAt       time.Time
}

// PasswordParams represents parameters for password operations
type PasswordParams struct {
	Password        []byte
	ID              uuid.UUID
	Username        string
	UsernameValid   bool
	PasswordVersion int32
}

// PasswordHistoryParams represents parameters for password history operations
type PasswordHistoryParams struct {
	LoginID uuid.UUID
	Limit   int32
}

// PasswordResetTokenParams represents parameters for password reset token operations
type PasswordResetTokenParams struct {
	LoginID  uuid.UUID
	Token    string
	ExpireAt time.Time
}

// PasswordToHistoryParams represents parameters for adding a password to history
type PasswordToHistoryParams struct {
	LoginID         uuid.UUID
	PasswordHash    []byte
	PasswordVersion int32
}

// LoginAttempt represents a login attempt record
type LoginAttempt struct {
	ID                uuid.UUID
	LoginID           uuid.UUID
	IPAddress         string
	UserAgent         string
	Success           bool
	FailureReason     string
	DeviceFingerprint string
	CreatedAt         time.Time
}

// UserRepository defines the interface for user-related database operations

// LoginRepository defines the interface for login-related database operations
type LoginRepository interface {
	// Login operations
	FindLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error)
	GetLoginById(ctx context.Context, id uuid.UUID) (LoginEntity, error)

	// Password operations
	GetPasswordVersion(ctx context.Context, id uuid.UUID) (int32, bool, error)
	ResetPassword(ctx context.Context, arg PasswordParams) error
	ResetPasswordById(ctx context.Context, arg PasswordParams) error
	UpdateUserPassword(ctx context.Context, arg PasswordParams) error
	UpdateUserPasswordAndVersion(ctx context.Context, arg PasswordParams) error
	GetPasswordUpdatedAt(ctx context.Context, loginID uuid.UUID) (time.Time, bool, error)
	GetPasswordExpiresAt(ctx context.Context, loginID uuid.UUID) (time.Time, bool, error)
	UpdatePasswordTimestamps(ctx context.Context, loginID uuid.UUID, updatedAt, expiresAt time.Time) error

	// Password reset token operations
	InitPasswordResetToken(ctx context.Context, arg PasswordResetTokenParams) error
	ValidatePasswordResetToken(ctx context.Context, token string) (PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, token string) error
	ExpirePasswordResetToken(ctx context.Context, loginID uuid.UUID) error
	InitPasswordByUsername(ctx context.Context, username string, usernameValid bool) (uuid.UUID, error)
	UpdatePasswordResetRequired(ctx context.Context, loginID uuid.UUID, required bool) error

	// Password history operations
	AddPasswordToHistory(ctx context.Context, arg PasswordToHistoryParams) error
	GetPasswordHistory(ctx context.Context, arg PasswordHistoryParams) ([]PasswordHistoryEntry, error)

	// Login attempt operations
	RecordLoginAttempt(ctx context.Context, attempt LoginAttempt) error
	GetRecentFailedAttempts(ctx context.Context, loginID uuid.UUID, since time.Time) (int, error)
	IsAccountLocked(ctx context.Context, loginID uuid.UUID) (bool, error)
	IncrementFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error
	LockAccount(ctx context.Context, loginID uuid.UUID, lockDuration time.Duration) error
	ResetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error
	GetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) (int32, time.Time, time.Time, error)

	// Passwordless login methods
	SetPasswordlessFlag(ctx context.Context, loginID uuid.UUID, isPasswordless bool) error
	IsPasswordlessLogin(ctx context.Context, loginID uuid.UUID) (bool, error)

	// Magic link methods
	GenerateMagicLinkToken(ctx context.Context, loginID uuid.UUID, token string, expiresAt time.Time) error
	ValidateMagicLinkToken(ctx context.Context, token string) (uuid.UUID, error)
	MarkMagicLinkTokenUsed(ctx context.Context, token string) error

	// Transaction support
	WithTx(tx interface{}) LoginRepository
}

// // InMemoryMagicLinkTokenRepository implements magic link token storage in memory
// type InMemoryMagicLinkTokenRepository struct {
// 	tokens      map[string]MagicLinkToken
// 	tokensMutex sync.RWMutex
// }

// NewInMemoryMagicLinkTokenRepository creates a new in-memory magic link token repository
// func NewInMemoryMagicLinkTokenRepository() *InMemoryMagicLinkTokenRepository {
// 	return &InMemoryMagicLinkTokenRepository{
// 		tokens: make(map[string]MagicLinkToken),
// 	}
// }

// PostgresLoginRepository implements LoginRepository using PostgreSQL
type PostgresLoginRepository struct {
	queries *logindb.Queries
	// magicLinkTokens    *InMemoryMagicLinkTokenRepository
	passwordlessLogins map[uuid.UUID]bool
	passwordlessMutex  sync.RWMutex
}

// PostgresLoginRepositoryAdapter adapts the PostgresLoginRepository to the LoginRepository interface
// while hiding the pgx implementation details
type PostgresLoginRepositoryAdapter interface {
	LoginRepository
	WithPgxTx(tx pgx.Tx) LoginRepository
}

// NewPostgresLoginRepository creates a new PostgreSQL-based login repository
func NewPostgresLoginRepository(queries *logindb.Queries) *PostgresLoginRepository {
	return &PostgresLoginRepository{
		queries: queries,
		// magicLinkTokens:    NewInMemoryMagicLinkTokenRepository(),
		passwordlessLogins: make(map[uuid.UUID]bool),
	}
}

// FindLoginByUsername finds a login by username
func (r *PostgresLoginRepository) FindLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error) {
	sqlUsername := sql.NullString{String: username, Valid: usernameValid}
	dbLogin, err := r.queries.FindLoginByUsername(ctx, sqlUsername)
	if err != nil {
		return LoginEntity{}, err
	}
	return LoginEntity{
		ID:                  dbLogin.ID,
		Username:            dbLogin.Username.String,
		UsernameValid:       dbLogin.Username.Valid,
		Password:            dbLogin.Password,
		PasswordVersion:     dbLogin.PasswordVersion.Int32,
		CreatedAt:           dbLogin.CreatedAt,
		UpdatedAt:           dbLogin.UpdatedAt,
		FailedLoginAttempts: dbLogin.FailedLoginAttempts.Int32,
		LastFailedAttemptAt: dbLogin.LastFailedAttemptAt.Time,
		LockedUntil:         dbLogin.LockedUntil.Time,
		PasswordUpdatedAt:   dbLogin.PasswordUpdatedAt.Time,
		PasswordExpiresAt:   dbLogin.PasswordExpiresAt.Time,
	}, nil
}

// GetLoginById returns a login by ID
func (r *PostgresLoginRepository) GetLoginById(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	dbLogin, err := r.queries.GetLoginById(ctx, id)
	if err != nil {
		return LoginEntity{}, err
	}
	return LoginEntity{
		ID:                  dbLogin.LoginID,
		Username:            dbLogin.Username.String,
		UsernameValid:       dbLogin.Username.Valid,
		Password:            dbLogin.Password,
		PasswordVersion:     0, // Not returned by this query
		CreatedAt:           dbLogin.CreatedAt,
		UpdatedAt:           dbLogin.UpdatedAt,
		FailedLoginAttempts: dbLogin.FailedLoginAttempts.Int32,
		LastFailedAttemptAt: dbLogin.LastFailedAttemptAt.Time,
		LockedUntil:         dbLogin.LockedUntil.Time,
	}, nil
}

// GetLoginByUserId gets a login by user ID
func (r *PostgresLoginRepository) GetLoginByUserId(ctx context.Context, userId uuid.UUID) (LoginEntity, error) {
	dbLogin, err := r.queries.GetLoginByUserId(ctx, userId)
	if err != nil {
		return LoginEntity{}, err
	}
	return LoginEntity{
		ID:                  dbLogin.LoginID,
		Username:            dbLogin.Username.String,
		UsernameValid:       dbLogin.Username.Valid,
		Password:            dbLogin.Password,
		PasswordVersion:     0, // Not returned by this query
		CreatedAt:           dbLogin.CreatedAt,
		UpdatedAt:           dbLogin.UpdatedAt,
		FailedLoginAttempts: dbLogin.FailedLoginAttempts.Int32,
		LastFailedAttemptAt: dbLogin.LastFailedAttemptAt.Time,
		LockedUntil:         dbLogin.LockedUntil.Time,
	}, nil
}

// GetPasswordVersion gets the password version for a login
func (r *PostgresLoginRepository) GetPasswordVersion(ctx context.Context, id uuid.UUID) (int32, bool, error) {
	version, err := r.queries.GetPasswordVersion(ctx, id)
	return version.Int32, version.Valid, err
}

// ResetPassword resets a password by username
func (r *PostgresLoginRepository) ResetPassword(ctx context.Context, arg PasswordParams) error {
	dbArg := logindb.ResetPasswordParams{
		Password: arg.Password,
		Username: sql.NullString{String: arg.Username, Valid: arg.UsernameValid},
	}
	return r.queries.ResetPassword(ctx, dbArg)
}

// ResetPasswordById resets a password by login ID
func (r *PostgresLoginRepository) ResetPasswordById(ctx context.Context, arg PasswordParams) error {
	dbArg := logindb.ResetPasswordByIdParams{
		Password: arg.Password,
		ID:       arg.ID,
	}
	return r.queries.ResetPasswordById(ctx, dbArg)
}

// UpdateUserPassword updates a user's password
func (r *PostgresLoginRepository) UpdateUserPassword(ctx context.Context, arg PasswordParams) error {
	dbArg := logindb.UpdateUserPasswordParams{
		Password: arg.Password,
		ID:       arg.ID,
	}
	return r.queries.UpdateUserPassword(ctx, dbArg)
}

// UpdateUserPasswordAndVersion updates a user's password and version
func (r *PostgresLoginRepository) UpdateUserPasswordAndVersion(ctx context.Context, arg PasswordParams) error {
	dbArg := logindb.UpdateUserPasswordAndVersionParams{
		Password:        arg.Password,
		ID:              arg.ID,
		PasswordVersion: pgtype.Int4{Int32: arg.PasswordVersion, Valid: true},
	}
	return r.queries.UpdateUserPasswordAndVersion(ctx, dbArg)
}

// InitPasswordResetToken initializes a password reset token
func (r *PostgresLoginRepository) InitPasswordResetToken(ctx context.Context, arg PasswordResetTokenParams) error {
	dbArg := logindb.InitPasswordResetTokenParams{
		LoginID:  arg.LoginID,
		Token:    arg.Token,
		ExpireAt: pgtype.Timestamptz{Time: arg.ExpireAt, Valid: true},
	}
	return r.queries.InitPasswordResetToken(ctx, dbArg)
}

// ValidatePasswordResetToken validates a password reset token
func (r *PostgresLoginRepository) ValidatePasswordResetToken(ctx context.Context, token string) (PasswordResetToken, error) {
	dbToken, err := r.queries.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return PasswordResetToken{}, err
	}
	return PasswordResetToken{
		ID:      dbToken.ID,
		LoginID: dbToken.LoginID,
	}, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used
func (r *PostgresLoginRepository) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	return r.queries.MarkPasswordResetTokenUsed(ctx, token)
}

// ExpirePasswordResetToken expires all password reset tokens for a login
func (r *PostgresLoginRepository) ExpirePasswordResetToken(ctx context.Context, loginID uuid.UUID) error {
	return r.queries.ExpirePasswordResetToken(ctx, loginID)
}

// InitPasswordByUsername initializes a password reset by username
func (r *PostgresLoginRepository) InitPasswordByUsername(ctx context.Context, username string, usernameValid bool) (uuid.UUID, error) {
	return r.queries.InitPasswordByUsername(ctx, sql.NullString{String: username, Valid: usernameValid})
}

func (r *PostgresLoginRepository) UpdatePasswordResetRequired(ctx context.Context, loginID uuid.UUID, required bool) error {
	requiredSql := sql.NullBool{Bool: required, Valid: true}
	return r.queries.UpdatePasswordResetRequired(ctx, logindb.UpdatePasswordResetRequiredParams{
		ID:                    loginID,
		PasswordResetRequired: requiredSql,
	})
}

// AddPasswordToHistory adds a password to the history
func (r *PostgresLoginRepository) AddPasswordToHistory(ctx context.Context, arg PasswordToHistoryParams) error {
	dbArg := logindb.AddPasswordToHistoryParams{
		LoginID:         arg.LoginID,
		PasswordHash:    arg.PasswordHash,
		PasswordVersion: arg.PasswordVersion,
	}
	return r.queries.AddPasswordToHistory(ctx, dbArg)
}

// GetPasswordHistory gets the password history for a login
func (r *PostgresLoginRepository) GetPasswordHistory(ctx context.Context, arg PasswordHistoryParams) ([]PasswordHistoryEntry, error) {
	dbArg := logindb.GetPasswordHistoryParams{
		LoginID: arg.LoginID,
		Limit:   arg.Limit,
	}
	dbHistory, err := r.queries.GetPasswordHistory(ctx, dbArg)
	if err != nil {
		return nil, err
	}

	history := make([]PasswordHistoryEntry, len(dbHistory))
	for i, entry := range dbHistory {
		history[i] = PasswordHistoryEntry{
			ID:              entry.ID,
			LoginID:         entry.LoginID,
			PasswordHash:    entry.PasswordHash,
			PasswordVersion: entry.PasswordVersion,
			CreatedAt:       entry.CreatedAt,
		}
	}
	return history, nil
}

// FindUserRolesByUserId finds user roles by user ID
func (r *PostgresLoginRepository) FindUserRolesByUserId(ctx context.Context, userID uuid.UUID) ([]string, error) {
	sqlRoles, err := r.queries.FindUserRolesByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}

	roles := make([]string, 0, len(sqlRoles))
	for _, role := range sqlRoles {
		if role.Valid {
			roles = append(roles, role.String)
		}
	}

	return roles, nil
}

// FindUserInfoWithRoles finds user info with roles
func (r *PostgresLoginRepository) FindUserInfoWithRoles(ctx context.Context, id uuid.UUID) (UserInfo, error) {
	dbUserInfo, err := r.queries.FindUserInfoWithRoles(ctx, id)
	if err != nil {
		return UserInfo{}, err
	}

	// Convert roles from interface{} to []string
	roles := []string{}
	if rolesArr, ok := dbUserInfo.Roles.([]interface{}); ok {
		for _, role := range rolesArr {
			if roleStr, ok := role.(string); ok {
				roles = append(roles, roleStr)
			}
		}
	}

	return UserInfo{
		Email:     dbUserInfo.Email,
		Name:      dbUserInfo.Name.String,
		NameValid: dbUserInfo.Name.Valid,
		Roles:     roles,
	}, nil
}

// FindUsernameByEmail finds a username by email
func (r *PostgresLoginRepository) FindUsernameByEmail(ctx context.Context, email string) (string, bool, error) {
	sqlUsername, err := r.queries.FindUsernameByEmail(ctx, email)
	if err != nil {
		return "", false, err
	}
	return sqlUsername.String, sqlUsername.Valid, nil
}

// GetUsersByLoginId gets users by login ID
func (r *PostgresLoginRepository) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID, loginIDValid bool) ([]UserWithRoles, error) {
	dbUsers, err := r.queries.GetUsersByLoginId(ctx, uuid.NullUUID{UUID: loginID, Valid: loginIDValid})
	if err != nil {
		return nil, err
	}

	users := make([]UserWithRoles, len(dbUsers))
	for i, user := range dbUsers {
		// Convert roles from interface{} to []string
		roles := []string{}
		if rolesArr, ok := user.Roles.([]interface{}); ok {
			for _, role := range rolesArr {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
		}

		users[i] = UserWithRoles{
			ID:             user.ID,
			Name:           user.Name.String,
			NameValid:      user.Name.Valid,
			Email:          user.Email,
			CreatedAt:      user.CreatedAt,
			LastModifiedAt: user.LastModifiedAt,
			Roles:          roles,
		}
	}
	return users, nil
}

// RecordLoginAttempt records a login attempt
func (r *PostgresLoginRepository) RecordLoginAttempt(ctx context.Context, attempt LoginAttempt) error {
	params := logindb.RecordLoginAttemptParams{
		ID:                uuid.New(),
		LoginID:           attempt.LoginID,
		IpAddress:         sql.NullString{String: attempt.IPAddress, Valid: attempt.IPAddress != ""},
		UserAgent:         sql.NullString{String: attempt.UserAgent, Valid: attempt.UserAgent != ""},
		Success:           attempt.Success,
		FailureReason:     sql.NullString{String: attempt.FailureReason, Valid: attempt.FailureReason != ""},
		DeviceFingerprint: sql.NullString{String: attempt.DeviceFingerprint, Valid: attempt.DeviceFingerprint != ""},
	}

	err := r.queries.RecordLoginAttempt(ctx, params)
	if err != nil {
		slog.Error("Failed to record login attempt", "err", err)
		return fmt.Errorf("failed to record login attempt: %w", err)
	}
	slog.Info("Login attempt recorded successfully", "loginID", attempt.LoginID, "success", attempt.Success)

	return nil
}

// GetRecentFailedAttempts returns the number of failed login attempts since the given time
func (r *PostgresLoginRepository) GetRecentFailedAttempts(ctx context.Context, loginID uuid.UUID, since time.Time) (int, error) {
	count, err := r.queries.GetRecentFailedAttempts(ctx, logindb.GetRecentFailedAttemptsParams{
		LoginID:   loginID,
		CreatedAt: since,
	})

	if err != nil {
		slog.Error("Failed to get recent failed attempts", "err", err)
		return 0, fmt.Errorf("failed to get recent failed attempts: %w", err)
	}

	return int(count), nil
}

// IsAccountLocked checks if an account is locked
func (r *PostgresLoginRepository) IsAccountLocked(ctx context.Context, loginID uuid.UUID) (bool, error) {
	isLocked, err := r.queries.IsAccountLocked(ctx, loginID)
	if err != nil {
		slog.Error("Failed to check if account is locked", "err", err)
		return false, fmt.Errorf("failed to check if account is locked: %w", err)
	}

	return isLocked, nil
}

// IncrementFailedLoginAttempts increments the failed login attempts for a login
func (r *PostgresLoginRepository) IncrementFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error {
	err := r.queries.IncrementFailedLoginAttempts(ctx, loginID)
	if err != nil {
		slog.Error("Failed to increment failed login attempts", "err", err)
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}

	return nil
}

// LockAccount locks an account
func (r *PostgresLoginRepository) LockAccount(ctx context.Context, loginID uuid.UUID, lockDuration time.Duration) error {
	lockedUntil := time.Now().Add(lockDuration)
	err := r.queries.LockAccount(ctx, logindb.LockAccountParams{
		ID:          loginID,
		LockedUntil: sql.NullTime{Time: lockedUntil, Valid: true},
	})

	if err != nil {
		slog.Error("Failed to lock account", "err", err)
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

// ResetFailedLoginAttempts resets the failed login attempts for a login
func (r *PostgresLoginRepository) ResetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error {
	err := r.queries.ResetFailedLoginAttempts(ctx, loginID)
	if err != nil {
		slog.Error("Failed to reset failed login attempts", "err", err)
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}

	return nil
}

// GetFailedLoginAttempts gets the failed login attempts for a login
func (r *PostgresLoginRepository) GetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) (int32, time.Time, time.Time, error) {
	row, err := r.queries.GetFailedLoginAttempts(ctx, loginID)
	if err != nil {
		return 0, time.Time{}, time.Time{}, err
	}

	failedAttempts := int32(0)
	if row.FailedLoginAttempts.Valid {
		failedAttempts = row.FailedLoginAttempts.Int32
	}

	lastFailedAt := time.Time{}
	if row.LastFailedAttemptAt.Valid {
		lastFailedAt = row.LastFailedAttemptAt.Time
	}

	lockedUntil := time.Time{}
	if row.LockedUntil.Valid {
		lockedUntil = row.LockedUntil.Time
	}

	return failedAttempts, lastFailedAt, lockedUntil, nil
}

// WithTx returns a new repository with the given transaction
func (r *PostgresLoginRepository) WithTx(tx interface{}) LoginRepository {
	// Check if the transaction is nil
	if tx == nil {
		return r
	}

	// Try to convert the interface to a pgx.Tx
	pgxTx, ok := tx.(pgx.Tx)
	if !ok {
		// If it's not a pgx.Tx, log a warning and return the original repository
		fmt.Printf("Warning: Unsupported transaction type: %v\n", reflect.TypeOf(tx))
		return r
	}

	// Use the pgx.Tx with the queries
	return &PostgresLoginRepository{
		queries: r.queries.WithTx(pgxTx),
		// magicLinkTokens:    r.magicLinkTokens,
		passwordlessLogins: r.passwordlessLogins,
	}
}

// WithPgxTx returns a new repository with the given pgx transaction
func (r *PostgresLoginRepository) WithPgxTx(tx pgx.Tx) LoginRepository {
	return &PostgresLoginRepository{
		queries: r.queries.WithTx(tx),
		// magicLinkTokens:    r.magicLinkTokens,
		passwordlessLogins: r.passwordlessLogins,
	}
}

// SetPasswordlessFlag sets whether a login uses passwordless authentication
func (r *PostgresLoginRepository) SetPasswordlessFlag(ctx context.Context, loginID uuid.UUID, isPasswordless bool) error {
	return r.queries.UpdatePasswordlessFlag(ctx, logindb.UpdatePasswordlessFlagParams{
		ID:             loginID,
		IsPasswordless: sql.NullBool{Bool: isPasswordless, Valid: true},
	})
}

// IsPasswordlessLogin checks if a login uses passwordless authentication
func (r *PostgresLoginRepository) IsPasswordlessLogin(ctx context.Context, loginID uuid.UUID) (bool, error) {
	nullBool, err := r.queries.GetPasswordlessFlag(ctx, loginID)
	if err != nil {
		return false, err
	}
	return nullBool.Bool, nil
}

// GenerateMagicLinkToken generates a magic link token
func (r *PostgresLoginRepository) GenerateMagicLinkToken(ctx context.Context, loginID uuid.UUID, token string, expiresAt time.Time) error {
	// Create the timestamp with explicit UTC time zone
	_, err := r.queries.CreateMagicLinkToken(ctx, logindb.CreateMagicLinkTokenParams{
		LoginID:   loginID,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	return err
}

// ValidateMagicLinkToken validates a magic link token
func (r *PostgresLoginRepository) ValidateMagicLinkToken(ctx context.Context, token string) (uuid.UUID, error) {
	tokenInfo, err := r.queries.ValidateMagicLinkToken(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, errors.New("token not found")
		}
		return uuid.Nil, fmt.Errorf("invalid or expired token: %w", err)
	}
	return tokenInfo.LoginID, nil
}

// MarkMagicLinkTokenUsed marks a magic link token as used
func (r *PostgresLoginRepository) MarkMagicLinkTokenUsed(ctx context.Context, token string) error {
	return r.queries.MarkMagicLinkTokenUsed(ctx, token)
}

// GetPasswordUpdatedAt gets the password updated at timestamp for a login
func (r *PostgresLoginRepository) GetPasswordUpdatedAt(ctx context.Context, id uuid.UUID) (time.Time, bool, error) {
	dbUpdatedAt, err := r.queries.GetPasswordUpdatedAt(ctx, id)
	if err != nil {
		slog.Error("Failed to get password updated at", "err", err)
		return time.Time{}, false, err
	}
	return dbUpdatedAt.Time, dbUpdatedAt.Valid, nil
}

// GetPasswordExpiresAt gets the password expire at timestamp for a login
func (r *PostgresLoginRepository) GetPasswordExpiresAt(ctx context.Context, id uuid.UUID) (time.Time, bool, error) {
	dbExpiresAt, err := r.queries.GetPasswordExpiresAt(ctx, id)
	if err != nil {
		slog.Error("Failed to get password expires at", "err", err)
		return time.Time{}, false, err
	}
	return dbExpiresAt.Time, dbExpiresAt.Valid, nil
}

// UpdatePasswordTimestamps updates the password updated at and expire at timestamps for a login
func (r *PostgresLoginRepository) UpdatePasswordTimestamps(ctx context.Context, id uuid.UUID, updatedAt, expiresAt time.Time) error {
	return r.queries.UpdatePasswordTimestamps(ctx, logindb.UpdatePasswordTimestampsParams{
		ID:                id,
		PasswordUpdatedAt: sql.NullTime{Time: updatedAt, Valid: true},
		PasswordExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
	})
}
