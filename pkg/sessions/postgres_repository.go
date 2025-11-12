package sessions

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository implements the Repository interface using PostgreSQL
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgreSQL session repository
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{
		pool: pool,
	}
}

// Create creates a new session
func (r *PostgresRepository) Create(ctx context.Context, req CreateSessionRequest) (*Session, error) {
	query := `
		INSERT INTO sessions (
			login_id, jti, token_type, issued_at, expires_at,
			ip_address, user_agent, device_fingerprint, device_name, device_type
		) VALUES (
			$1, $2, $3, NOW(), $4, $5, $6, $7, $8, $9
		) RETURNING
			id, login_id, jti, token_type, issued_at, expires_at, revoked_at,
			ip_address, user_agent, device_fingerprint, device_name, device_type,
			last_activity, created_at, updated_at
	`

	session := &Session{}
	var revokedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query,
		req.LoginID,
		req.JTI,
		req.TokenType,
		req.ExpiresAt,
		req.IPAddress,
		req.UserAgent,
		req.DeviceFingerprint,
		req.DeviceName,
		req.DeviceType,
	).Scan(
		&session.ID,
		&session.LoginID,
		&session.JTI,
		&session.TokenType,
		&session.IssuedAt,
		&session.ExpiresAt,
		&revokedAt,
		&session.IPAddress,
		&session.UserAgent,
		&session.DeviceFingerprint,
		&session.DeviceName,
		&session.DeviceType,
		&session.LastActivity,
		&session.CreatedAt,
		&session.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}

	return session, nil
}

// GetByID retrieves a session by its ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*Session, error) {
	query := `
		SELECT
			id, login_id, jti, token_type, issued_at, expires_at, revoked_at,
			ip_address, user_agent, device_fingerprint, device_name, device_type,
			last_activity, created_at, updated_at
		FROM sessions
		WHERE id = $1
	`

	session := &Session{}
	var revokedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.LoginID,
		&session.JTI,
		&session.TokenType,
		&session.IssuedAt,
		&session.ExpiresAt,
		&revokedAt,
		&session.IPAddress,
		&session.UserAgent,
		&session.DeviceFingerprint,
		&session.DeviceName,
		&session.DeviceType,
		&session.LastActivity,
		&session.CreatedAt,
		&session.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}

	return session, nil
}

// GetByJTI retrieves a session by its JTI
func (r *PostgresRepository) GetByJTI(ctx context.Context, jti string) (*Session, error) {
	query := `
		SELECT
			id, login_id, jti, token_type, issued_at, expires_at, revoked_at,
			ip_address, user_agent, device_fingerprint, device_name, device_type,
			last_activity, created_at, updated_at
		FROM sessions
		WHERE jti = $1
	`

	session := &Session{}
	var revokedAt sql.NullTime

	err := r.pool.QueryRow(ctx, query, jti).Scan(
		&session.ID,
		&session.LoginID,
		&session.JTI,
		&session.TokenType,
		&session.IssuedAt,
		&session.ExpiresAt,
		&revokedAt,
		&session.IPAddress,
		&session.UserAgent,
		&session.DeviceFingerprint,
		&session.DeviceName,
		&session.DeviceType,
		&session.LastActivity,
		&session.CreatedAt,
		&session.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get session by JTI: %w", err)
	}

	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}

	return session, nil
}

// ListActiveByLoginID lists all active sessions for a login
func (r *PostgresRepository) ListActiveByLoginID(ctx context.Context, loginID uuid.UUID) ([]Session, error) {
	query := `
		SELECT
			id, login_id, jti, token_type, issued_at, expires_at, revoked_at,
			ip_address, user_agent, device_fingerprint, device_name, device_type,
			last_activity, created_at, updated_at
		FROM sessions
		WHERE login_id = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		ORDER BY last_activity DESC
	`

	rows, err := r.pool.Query(ctx, query, loginID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		var revokedAt sql.NullTime

		err := rows.Scan(
			&session.ID,
			&session.LoginID,
			&session.JTI,
			&session.TokenType,
			&session.IssuedAt,
			&session.ExpiresAt,
			&revokedAt,
			&session.IPAddress,
			&session.UserAgent,
			&session.DeviceFingerprint,
			&session.DeviceName,
			&session.DeviceType,
			&session.LastActivity,
			&session.CreatedAt,
			&session.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		if revokedAt.Valid {
			session.RevokedAt = &revokedAt.Time
		}

		sessions = append(sessions, session)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("error iterating sessions: %w", rows.Err())
	}

	return sessions, nil
}

// ListByLoginID lists all sessions for a login with pagination
func (r *PostgresRepository) ListByLoginID(ctx context.Context, loginID uuid.UUID, limit, offset int) ([]Session, error) {
	query := `
		SELECT
			id, login_id, jti, token_type, issued_at, expires_at, revoked_at,
			ip_address, user_agent, device_fingerprint, device_name, device_type,
			last_activity, created_at, updated_at
		FROM sessions
		WHERE login_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, loginID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		var revokedAt sql.NullTime

		err := rows.Scan(
			&session.ID,
			&session.LoginID,
			&session.JTI,
			&session.TokenType,
			&session.IssuedAt,
			&session.ExpiresAt,
			&revokedAt,
			&session.IPAddress,
			&session.UserAgent,
			&session.DeviceFingerprint,
			&session.DeviceName,
			&session.DeviceType,
			&session.LastActivity,
			&session.CreatedAt,
			&session.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		if revokedAt.Valid {
			session.RevokedAt = &revokedAt.Time
		}

		sessions = append(sessions, session)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("error iterating sessions: %w", rows.Err())
	}

	return sessions, nil
}

// CountActiveByLoginID counts active sessions for a login
func (r *PostgresRepository) CountActiveByLoginID(ctx context.Context, loginID uuid.UUID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM sessions
		WHERE login_id = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`

	var count int
	err := r.pool.QueryRow(ctx, query, loginID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}

	return count, nil
}

// Revoke revokes a session by ID
func (r *PostgresRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
		  AND revoked_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("session not found or already revoked")
	}

	return nil
}

// RevokeByJTI revokes a session by JTI
func (r *PostgresRepository) RevokeByJTI(ctx context.Context, jti string) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    updated_at = NOW()
		WHERE jti = $1
		  AND revoked_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, jti)
	if err != nil {
		return fmt.Errorf("failed to revoke session by JTI: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("session not found or already revoked")
	}

	return nil
}

// RevokeAllByLoginID revokes all sessions for a login
func (r *PostgresRepository) RevokeAllByLoginID(ctx context.Context, loginID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    updated_at = NOW()
		WHERE login_id = $1
		  AND revoked_at IS NULL
	`

	_, err := r.pool.Exec(ctx, query, loginID)
	if err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	return nil
}

// RevokeAllExceptCurrent revokes all sessions except the current one
func (r *PostgresRepository) RevokeAllExceptCurrent(ctx context.Context, loginID uuid.UUID, currentSessionID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(),
		    updated_at = NOW()
		WHERE login_id = $1
		  AND id != $2
		  AND revoked_at IS NULL
	`

	_, err := r.pool.Exec(ctx, query, loginID, currentSessionID)
	if err != nil {
		return fmt.Errorf("failed to revoke all sessions except current: %w", err)
	}

	return nil
}

// UpdateActivity updates the last activity timestamp
func (r *PostgresRepository) UpdateActivity(ctx context.Context, jti string) error {
	query := `
		UPDATE sessions
		SET last_activity = NOW(),
		    updated_at = NOW()
		WHERE jti = $1
	`

	_, err := r.pool.Exec(ctx, query, jti)
	if err != nil {
		return fmt.Errorf("failed to update activity: %w", err)
	}

	return nil
}

// IsRevoked checks if a session is revoked
func (r *PostgresRepository) IsRevoked(ctx context.Context, jti string) (bool, error) {
	query := `
		SELECT (revoked_at IS NOT NULL) as is_revoked
		FROM sessions
		WHERE jti = $1
	`

	var isRevoked bool
	err := r.pool.QueryRow(ctx, query, jti).Scan(&isRevoked)
	if err != nil {
		return false, fmt.Errorf("failed to check if session is revoked: %w", err)
	}

	return isRevoked, nil
}

// IsValid checks if a session is valid (not revoked and not expired)
func (r *PostgresRepository) IsValid(ctx context.Context, jti string) (bool, error) {
	query := `
		SELECT (
			revoked_at IS NULL
			AND expires_at > NOW()
		) as is_valid
		FROM sessions
		WHERE jti = $1
	`

	var isValid bool
	err := r.pool.QueryRow(ctx, query, jti).Scan(&isValid)
	if err != nil {
		return false, fmt.Errorf("failed to check if session is valid: %w", err)
	}

	return isValid, nil
}

// DeleteExpired deletes expired sessions
func (r *PostgresRepository) DeleteExpired(ctx context.Context) error {
	query := `
		DELETE FROM sessions
		WHERE expires_at < NOW()
	`

	_, err := r.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return nil
}

// DeleteOldRevoked deletes old revoked sessions (older than 7 days)
func (r *PostgresRepository) DeleteOldRevoked(ctx context.Context) error {
	query := `
		DELETE FROM sessions
		WHERE revoked_at IS NOT NULL
		  AND revoked_at < NOW() - INTERVAL '7 days'
	`

	_, err := r.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete old revoked sessions: %w", err)
	}

	return nil
}
