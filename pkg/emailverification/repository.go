package emailverification

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerificationToken represents an email verification token
type VerificationToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Token      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	VerifiedAt *time.Time
	DeletedAt  *time.Time
}

// UserEmailStatus represents a user's email verification status
type UserEmailStatus struct {
	ID              uuid.UUID
	Email           string
	Name            string
	EmailVerified   bool
	EmailVerifiedAt *time.Time
}

// Repository handles database operations for email verification
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new email verification repository
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// CreateVerificationToken creates a new verification token
func (r *Repository) CreateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*VerificationToken, error) {
	query := `
		INSERT INTO email_verification_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, token, created_at, expires_at, verified_at, deleted_at
	`

	var vt VerificationToken
	err := r.db.QueryRow(ctx, query, userID, token, expiresAt).Scan(
		&vt.ID,
		&vt.UserID,
		&vt.Token,
		&vt.CreatedAt,
		&vt.ExpiresAt,
		&vt.VerifiedAt,
		&vt.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return &vt, nil
}

// GetVerificationTokenByToken retrieves an active verification token
func (r *Repository) GetVerificationTokenByToken(ctx context.Context, token string) (*VerificationToken, error) {
	query := `
		SELECT id, user_id, token, created_at, expires_at, verified_at, deleted_at
		FROM email_verification_tokens
		WHERE token = $1
		AND deleted_at IS NULL
		AND verified_at IS NULL
	`

	var vt VerificationToken
	err := r.db.QueryRow(ctx, query, token).Scan(
		&vt.ID,
		&vt.UserID,
		&vt.Token,
		&vt.CreatedAt,
		&vt.ExpiresAt,
		&vt.VerifiedAt,
		&vt.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	return &vt, nil
}

// GetActiveTokensByUserId retrieves all active tokens for a user
func (r *Repository) GetActiveTokensByUserId(ctx context.Context, userID uuid.UUID) ([]*VerificationToken, error) {
	query := `
		SELECT id, user_id, token, created_at, expires_at, verified_at, deleted_at
		FROM email_verification_tokens
		WHERE user_id = $1
		AND deleted_at IS NULL
		AND verified_at IS NULL
		AND expires_at > NOW() AT TIME ZONE 'UTC'
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*VerificationToken
	for rows.Next() {
		var vt VerificationToken
		if err := rows.Scan(
			&vt.ID,
			&vt.UserID,
			&vt.Token,
			&vt.CreatedAt,
			&vt.ExpiresAt,
			&vt.VerifiedAt,
			&vt.DeletedAt,
		); err != nil {
			return nil, err
		}
		tokens = append(tokens, &vt)
	}

	return tokens, rows.Err()
}

// MarkTokenAsVerified marks a token as verified
func (r *Repository) MarkTokenAsVerified(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE email_verification_tokens
		SET verified_at = NOW() AT TIME ZONE 'UTC'
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, tokenID)
	return err
}

// SoftDeleteToken soft deletes a token
func (r *Repository) SoftDeleteToken(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE email_verification_tokens
		SET deleted_at = NOW() AT TIME ZONE 'UTC'
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, tokenID)
	return err
}

// SoftDeleteUserTokens soft deletes all tokens for a user
func (r *Repository) SoftDeleteUserTokens(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE email_verification_tokens
		SET deleted_at = NOW() AT TIME ZONE 'UTC'
		WHERE user_id = $1
		AND deleted_at IS NULL
	`

	_, err := r.db.Exec(ctx, query, userID)
	return err
}

// MarkUserEmailAsVerified marks a user's email as verified
func (r *Repository) MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users
		SET email_verified = TRUE,
		    email_verified_at = NOW() AT TIME ZONE 'UTC'
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	return err
}

// GetUserEmailVerificationStatus gets a user's email verification status
func (r *Repository) GetUserEmailVerificationStatus(ctx context.Context, userID uuid.UUID) (*UserEmailStatus, error) {
	query := `
		SELECT id, email, name, email_verified, email_verified_at
		FROM users
		WHERE id = $1
		AND deleted_at IS NULL
	`

	var status UserEmailStatus
	var name sql.NullString
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&status.ID,
		&status.Email,
		&name,
		&status.EmailVerified,
		&status.EmailVerifiedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if name.Valid {
		status.Name = name.String
	}

	return &status, nil
}

// CountRecentTokensByUserId counts recent tokens for rate limiting
func (r *Repository) CountRecentTokensByUserId(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM email_verification_tokens
		WHERE user_id = $1
		AND created_at > $2
		AND deleted_at IS NULL
	`

	var count int64
	err := r.db.QueryRow(ctx, query, userID, since).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// CleanupExpiredTokens soft deletes expired tokens
func (r *Repository) CleanupExpiredTokens(ctx context.Context) error {
	query := `
		UPDATE email_verification_tokens
		SET deleted_at = NOW() AT TIME ZONE 'UTC'
		WHERE expires_at < NOW() AT TIME ZONE 'UTC'
		AND deleted_at IS NULL
		AND verified_at IS NULL
	`

	_, err := r.db.Exec(ctx, query)
	return err
}

// GetUserByEmail retrieves a user by email
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*UserEmailStatus, error) {
	query := `
		SELECT id, email, name, email_verified, email_verified_at
		FROM users
		WHERE email = $1
		AND deleted_at IS NULL
	`

	var status UserEmailStatus
	var name sql.NullString
	err := r.db.QueryRow(ctx, query, email).Scan(
		&status.ID,
		&status.Email,
		&name,
		&status.EmailVerified,
		&status.EmailVerifiedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if name.Valid {
		status.Name = name.String
	}

	return &status, nil
}
