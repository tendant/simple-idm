package login

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/login/logindb"
)

// Domain models for the login repository

// LoginEntity represents a user login record in the domain model
type LoginEntity struct {
	ID              uuid.UUID
	Username        string
	UsernameValid   bool
	Password        []byte
	PasswordVersion int32
	CreatedAt       time.Time
	UpdatedAt       time.Time
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

	// Transaction support
	WithTx(tx interface{}) LoginRepository
}

// PostgresLoginRepository implements LoginRepository and UserRepository using PostgreSQL
type PostgresLoginRepository struct {
	queries *logindb.Queries
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
		ID:              dbLogin.ID,
		Username:        dbLogin.Username.String,
		UsernameValid:   dbLogin.Username.Valid,
		Password:        dbLogin.Password,
		PasswordVersion: dbLogin.PasswordVersion.Int32,
		CreatedAt:       dbLogin.CreatedAt,
		UpdatedAt:       dbLogin.UpdatedAt,
	}, nil
}

// GetLoginById gets a login by ID
func (r *PostgresLoginRepository) GetLoginById(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	dbLogin, err := r.queries.GetLoginById(ctx, id)
	if err != nil {
		return LoginEntity{}, err
	}
	return LoginEntity{
		ID:              dbLogin.LoginID,
		Username:        dbLogin.Username.String,
		UsernameValid:   dbLogin.Username.Valid,
		Password:        dbLogin.Password,
		PasswordVersion: 0, // Not returned by this query
		CreatedAt:       dbLogin.CreatedAt,
		UpdatedAt:       dbLogin.UpdatedAt,
	}, nil
}

// GetLoginByUserId gets a login by user ID
func (r *PostgresLoginRepository) GetLoginByUserId(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	dbLogin, err := r.queries.GetLoginByUserId(ctx, id)
	if err != nil {
		return LoginEntity{}, err
	}
	return LoginEntity{
		ID:              dbLogin.LoginID,
		Username:        dbLogin.Username.String,
		UsernameValid:   dbLogin.Username.Valid,
		Password:        dbLogin.Password,
		PasswordVersion: 0, // Not returned by this query
		CreatedAt:       dbLogin.CreatedAt,
		UpdatedAt:       dbLogin.UpdatedAt,
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
	}
}

// WithPgxTx returns a new repository with the given pgx transaction
func (r *PostgresLoginRepository) WithPgxTx(tx pgx.Tx) LoginRepository {
	return &PostgresLoginRepository{
		queries: r.queries.WithTx(tx),
	}
}
