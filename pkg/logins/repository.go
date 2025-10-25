package logins

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
)

// Domain models for the logins repository

// LoginEntity represents a login record in the domain model
type LoginEntity struct {
	ID              uuid.UUID
	Username        string
	UsernameValid   bool
	Password        []byte
	PasswordVersion int32
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       time.Time
	DeletedAtValid  bool
	CreatedBy       string
	CreatedByValid  bool
}

// CreateLoginParams represents parameters for creating a login
type CreateLoginParams struct {
	Username      string
	UsernameValid bool
	Password      []byte
	CreatedBy     string
	CreatedByValid bool
}

// UpdateLoginParams represents parameters for updating a login
type UpdateLoginParams struct {
	ID            uuid.UUID
	Username      string
	UsernameValid bool
}

// ListLoginsParams represents parameters for listing logins
type ListLoginsParams struct {
	Limit  int32
	Offset int32
}

// SearchLoginsParams represents parameters for searching logins
type SearchLoginsParams struct {
	Query  string
	Limit  int32
	Offset int32
}

// LoginsRepository defines the interface for logins-related database operations
type LoginsRepository interface {
	// Login operations
	GetLogin(ctx context.Context, id uuid.UUID) (LoginEntity, error)
	GetLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error)
	ListLogins(ctx context.Context, params ListLoginsParams) ([]LoginEntity, error)
	CountLogins(ctx context.Context) (int64, error)
	SearchLogins(ctx context.Context, params SearchLoginsParams) ([]LoginEntity, error)
	CreateLogin(ctx context.Context, params CreateLoginParams) (LoginEntity, error)
	UpdateLogin(ctx context.Context, params UpdateLoginParams) (LoginEntity, error)
	DeleteLogin(ctx context.Context, id uuid.UUID) error

	// Transaction support
	WithTx(tx interface{}) LoginsRepository
}

// PostgresLoginsRepository implements LoginsRepository using PostgreSQL
type PostgresLoginsRepository struct {
	queries *loginsdb.Queries
}

// NewPostgresLoginsRepository creates a new PostgreSQL-based logins repository
func NewPostgresLoginsRepository(queries *loginsdb.Queries) *PostgresLoginsRepository {
	return &PostgresLoginsRepository{
		queries: queries,
	}
}

// GetLogin retrieves a login by ID
func (r *PostgresLoginsRepository) GetLogin(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	dbLogin, err := r.queries.GetLogin(ctx, id)
	if err != nil {
		return LoginEntity{}, err
	}
	return r.toLoginEntity(dbLogin), nil
}

// GetLoginByUsername retrieves a login by username
func (r *PostgresLoginsRepository) GetLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error) {
	sqlUsername := sql.NullString{String: username, Valid: usernameValid}
	dbLogin, err := r.queries.GetLoginByUsername(ctx, sqlUsername)
	if err != nil {
		return LoginEntity{}, err
	}
	return r.toLoginEntity(dbLogin), nil
}

// ListLogins retrieves a list of logins with pagination
func (r *PostgresLoginsRepository) ListLogins(ctx context.Context, params ListLoginsParams) ([]LoginEntity, error) {
	dbLogins, err := r.queries.ListLogins(ctx, loginsdb.ListLoginsParams{
		Limit:  params.Limit,
		Offset: params.Offset,
	})
	if err != nil {
		return nil, err
	}

	logins := make([]LoginEntity, len(dbLogins))
	for i, dbLogin := range dbLogins {
		logins[i] = r.toLoginEntity(dbLogin)
	}
	return logins, nil
}

// CountLogins returns the total number of logins
func (r *PostgresLoginsRepository) CountLogins(ctx context.Context) (int64, error) {
	return r.queries.CountLogins(ctx)
}

// SearchLogins searches for logins by username pattern
func (r *PostgresLoginsRepository) SearchLogins(ctx context.Context, params SearchLoginsParams) ([]LoginEntity, error) {
	searchText := pgtype.Text{String: params.Query, Valid: true}
	dbLogins, err := r.queries.SearchLogins(ctx, loginsdb.SearchLoginsParams{
		Column1: searchText,
		Limit:   params.Limit,
		Offset:  params.Offset,
	})
	if err != nil {
		return nil, err
	}

	logins := make([]LoginEntity, len(dbLogins))
	for i, dbLogin := range dbLogins {
		logins[i] = r.toLoginEntity(dbLogin)
	}
	return logins, nil
}

// CreateLogin creates a new login
func (r *PostgresLoginsRepository) CreateLogin(ctx context.Context, params CreateLoginParams) (LoginEntity, error) {
	dbParams := loginsdb.CreateLoginParams{
		Username:  sql.NullString{String: params.Username, Valid: params.UsernameValid},
		Password:  params.Password,
		CreatedBy: sql.NullString{String: params.CreatedBy, Valid: params.CreatedByValid},
	}
	dbLogin, err := r.queries.CreateLogin(ctx, dbParams)
	if err != nil {
		return LoginEntity{}, err
	}
	return r.toLoginEntity(dbLogin), nil
}

// UpdateLogin updates a login's username
func (r *PostgresLoginsRepository) UpdateLogin(ctx context.Context, params UpdateLoginParams) (LoginEntity, error) {
	dbParams := loginsdb.UpdateLoginParams{
		ID:       params.ID,
		Username: sql.NullString{String: params.Username, Valid: params.UsernameValid},
	}
	dbLogin, err := r.queries.UpdateLogin(ctx, dbParams)
	if err != nil {
		return LoginEntity{}, err
	}
	return r.toLoginEntity(dbLogin), nil
}

// DeleteLogin soft deletes a login
func (r *PostgresLoginsRepository) DeleteLogin(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteLogin(ctx, id)
}

// WithTx returns a new repository with the given transaction
func (r *PostgresLoginsRepository) WithTx(tx interface{}) LoginsRepository {
	if tx == nil {
		return r
	}

	pgxTx, ok := tx.(pgx.Tx)
	if !ok {
		return r
	}

	return &PostgresLoginsRepository{
		queries: r.queries.WithTx(pgxTx),
	}
}

// toLoginEntity converts a database Login to a LoginEntity
func (r *PostgresLoginsRepository) toLoginEntity(dbLogin loginsdb.Login) LoginEntity {
	return LoginEntity{
		ID:              dbLogin.ID,
		Username:        dbLogin.Username.String,
		UsernameValid:   dbLogin.Username.Valid,
		Password:        dbLogin.Password,
		PasswordVersion: dbLogin.PasswordVersion.Int32,
		CreatedAt:       dbLogin.CreatedAt,
		UpdatedAt:       dbLogin.UpdatedAt,
		DeletedAt:       dbLogin.DeletedAt.Time,
		DeletedAtValid:  dbLogin.DeletedAt.Valid,
		CreatedBy:       dbLogin.CreatedBy.String,
		CreatedByValid:  dbLogin.CreatedBy.Valid,
	}
}
