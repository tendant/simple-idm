package login

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/login/logindb"
)

// LoginRepository defines the interface for login-related database operations
type LoginRepository interface {
	// Login operations
	FindLoginByUsername(ctx context.Context, username sql.NullString) (logindb.FindLoginByUsernameRow, error)
	GetLoginById(ctx context.Context, id uuid.UUID) (logindb.GetLoginByIdRow, error)
	GetLoginByUserId(ctx context.Context, id uuid.UUID) (logindb.GetLoginByUserIdRow, error)
	
	// Password operations
	GetPasswordVersion(ctx context.Context, id uuid.UUID) (pgtype.Int4, error)
	ResetPassword(ctx context.Context, arg logindb.ResetPasswordParams) error
	ResetPasswordById(ctx context.Context, arg logindb.ResetPasswordByIdParams) error
	UpdateUserPassword(ctx context.Context, arg logindb.UpdateUserPasswordParams) error
	UpdateUserPasswordAndVersion(ctx context.Context, arg logindb.UpdateUserPasswordAndVersionParams) error
	
	// Password reset token operations
	InitPasswordResetToken(ctx context.Context, arg logindb.InitPasswordResetTokenParams) error
	ValidatePasswordResetToken(ctx context.Context, token string) (logindb.ValidatePasswordResetTokenRow, error)
	MarkPasswordResetTokenUsed(ctx context.Context, token string) error
	ExpirePasswordResetToken(ctx context.Context, loginID uuid.UUID) error
	InitPasswordByUsername(ctx context.Context, username sql.NullString) (uuid.UUID, error)
	
	// Password history operations
	AddPasswordToHistory(ctx context.Context, arg logindb.AddPasswordToHistoryParams) error
	GetPasswordHistory(ctx context.Context, arg logindb.GetPasswordHistoryParams) ([]logindb.GetPasswordHistoryRow, error)
	
	// User operations
	FindUserRolesByUserId(ctx context.Context, userID uuid.UUID) ([]sql.NullString, error)
	FindUserInfoWithRoles(ctx context.Context, id uuid.UUID) (logindb.FindUserInfoWithRolesRow, error)
	FindUsernameByEmail(ctx context.Context, email string) (sql.NullString, error)
	GetUsersByLoginId(ctx context.Context, loginID uuid.NullUUID) ([]logindb.GetUsersByLoginIdRow, error)
	
	// Transaction support
	WithTx(tx interface{}) LoginRepository
}

// PostgresLoginRepository implements LoginRepository using PostgreSQL
type PostgresLoginRepository struct {
	queries *logindb.Queries
}

// NewPostgresLoginRepository creates a new PostgreSQL-based login repository
func NewPostgresLoginRepository(queries *logindb.Queries) *PostgresLoginRepository {
	return &PostgresLoginRepository{
		queries: queries,
	}
}

// FindLoginByUsername finds a login by username
func (r *PostgresLoginRepository) FindLoginByUsername(ctx context.Context, username sql.NullString) (logindb.FindLoginByUsernameRow, error) {
	return r.queries.FindLoginByUsername(ctx, username)
}

// GetLoginById gets a login by ID
func (r *PostgresLoginRepository) GetLoginById(ctx context.Context, id uuid.UUID) (logindb.GetLoginByIdRow, error) {
	return r.queries.GetLoginById(ctx, id)
}

// GetLoginByUserId gets a login by user ID
func (r *PostgresLoginRepository) GetLoginByUserId(ctx context.Context, id uuid.UUID) (logindb.GetLoginByUserIdRow, error) {
	return r.queries.GetLoginByUserId(ctx, id)
}

// GetPasswordVersion gets the password version for a login
func (r *PostgresLoginRepository) GetPasswordVersion(ctx context.Context, id uuid.UUID) (pgtype.Int4, error) {
	return r.queries.GetPasswordVersion(ctx, id)
}

// ResetPassword resets a password by username
func (r *PostgresLoginRepository) ResetPassword(ctx context.Context, arg logindb.ResetPasswordParams) error {
	return r.queries.ResetPassword(ctx, arg)
}

// ResetPasswordById resets a password by login ID
func (r *PostgresLoginRepository) ResetPasswordById(ctx context.Context, arg logindb.ResetPasswordByIdParams) error {
	return r.queries.ResetPasswordById(ctx, arg)
}

// UpdateUserPassword updates a user's password
func (r *PostgresLoginRepository) UpdateUserPassword(ctx context.Context, arg logindb.UpdateUserPasswordParams) error {
	return r.queries.UpdateUserPassword(ctx, arg)
}

// UpdateUserPasswordAndVersion updates a user's password and version
func (r *PostgresLoginRepository) UpdateUserPasswordAndVersion(ctx context.Context, arg logindb.UpdateUserPasswordAndVersionParams) error {
	return r.queries.UpdateUserPasswordAndVersion(ctx, arg)
}

// InitPasswordResetToken initializes a password reset token
func (r *PostgresLoginRepository) InitPasswordResetToken(ctx context.Context, arg logindb.InitPasswordResetTokenParams) error {
	return r.queries.InitPasswordResetToken(ctx, arg)
}

// ValidatePasswordResetToken validates a password reset token
func (r *PostgresLoginRepository) ValidatePasswordResetToken(ctx context.Context, token string) (logindb.ValidatePasswordResetTokenRow, error) {
	return r.queries.ValidatePasswordResetToken(ctx, token)
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
func (r *PostgresLoginRepository) InitPasswordByUsername(ctx context.Context, username sql.NullString) (uuid.UUID, error) {
	return r.queries.InitPasswordByUsername(ctx, username)
}

// AddPasswordToHistory adds a password to the history
func (r *PostgresLoginRepository) AddPasswordToHistory(ctx context.Context, arg logindb.AddPasswordToHistoryParams) error {
	return r.queries.AddPasswordToHistory(ctx, arg)
}

// GetPasswordHistory gets the password history for a login
func (r *PostgresLoginRepository) GetPasswordHistory(ctx context.Context, arg logindb.GetPasswordHistoryParams) ([]logindb.GetPasswordHistoryRow, error) {
	return r.queries.GetPasswordHistory(ctx, arg)
}

// FindUserRolesByUserId finds user roles by user ID
func (r *PostgresLoginRepository) FindUserRolesByUserId(ctx context.Context, userID uuid.UUID) ([]sql.NullString, error) {
	return r.queries.FindUserRolesByUserId(ctx, userID)
}

// FindUserInfoWithRoles finds user info with roles
func (r *PostgresLoginRepository) FindUserInfoWithRoles(ctx context.Context, id uuid.UUID) (logindb.FindUserInfoWithRolesRow, error) {
	return r.queries.FindUserInfoWithRoles(ctx, id)
}

// FindUsernameByEmail finds a username by email
func (r *PostgresLoginRepository) FindUsernameByEmail(ctx context.Context, email string) (sql.NullString, error) {
	return r.queries.FindUsernameByEmail(ctx, email)
}

// GetUsersByLoginId gets users by login ID
func (r *PostgresLoginRepository) GetUsersByLoginId(ctx context.Context, loginID uuid.NullUUID) ([]logindb.GetUsersByLoginIdRow, error) {
	return r.queries.GetUsersByLoginId(ctx, loginID)
}

// WithTx returns a new repository with the given transaction
func (r *PostgresLoginRepository) WithTx(tx interface{}) LoginRepository {
	if pgxTx, ok := tx.(pgx.Tx); ok {
		return &PostgresLoginRepository{
			queries: r.queries.WithTx(pgxTx),
		}
	}
	return r
}
