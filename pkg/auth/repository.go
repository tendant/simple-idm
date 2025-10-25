package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/auth/db"
)

// UserAuthEntity represents user authentication data without database-specific types
type UserAuthEntity struct {
	UUID         uuid.UUID
	Name         string
	NameValid    bool
	Username     string
	UsernameValid bool
	Email        string
	Password     string
	PasswordValid bool
}

// UpdatePasswordParams represents the parameters for updating a user's password
type UpdatePasswordParams struct {
	UserID         uuid.UUID
	Password       string
	LastModifiedAt time.Time
}

// AuthRepository defines the interface for authentication operations
type AuthRepository interface {
	FindUserByUserUUID(ctx context.Context, userUUID uuid.UUID) (UserAuthEntity, error)
	UpdatePassword(ctx context.Context, params UpdatePasswordParams) error
}

// PostgresAuthRepository implements AuthRepository using PostgreSQL
type PostgresAuthRepository struct {
	queries *db.Queries
}

// NewPostgresAuthRepository creates a new PostgreSQL-based auth repository
func NewPostgresAuthRepository(queries *db.Queries) *PostgresAuthRepository {
	return &PostgresAuthRepository{
		queries: queries,
	}
}

// FindUserByUserUUID retrieves user authentication data by user UUID
func (r *PostgresAuthRepository) FindUserByUserUUID(ctx context.Context, userUUID uuid.UUID) (UserAuthEntity, error) {
	row, err := r.queries.FindUserByUserUuid(ctx, userUUID)
	if err != nil {
		return UserAuthEntity{}, err
	}

	return UserAuthEntity{
		UUID:          row.Uuid,
		Name:          row.Name.String,
		NameValid:     row.Name.Valid,
		Username:      row.Username.String,
		UsernameValid: row.Username.Valid,
		Email:         row.Email,
		Password:      row.Password.String,
		PasswordValid: row.Password.Valid,
	}, nil
}

// UpdatePassword updates a user's password
func (r *PostgresAuthRepository) UpdatePassword(ctx context.Context, params UpdatePasswordParams) error {
	return r.queries.UpdatePassowrd(ctx, db.UpdatePassowrdParams{
		Password:       sql.NullString{Valid: true, String: params.Password},
		LastModifiedAt: params.LastModifiedAt,
		Uuid:           params.UserID,
	})
}
