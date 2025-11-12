package sessions

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the interface for session data access
type Repository interface {
	// Create a new session
	Create(ctx context.Context, req CreateSessionRequest) (*Session, error)

	// Get a session by ID
	GetByID(ctx context.Context, id uuid.UUID) (*Session, error)

	// Get a session by JTI (JWT ID)
	GetByJTI(ctx context.Context, jti string) (*Session, error)

	// List active sessions for a login
	ListActiveByLoginID(ctx context.Context, loginID uuid.UUID) ([]Session, error)

	// List all sessions for a login with pagination
	ListByLoginID(ctx context.Context, loginID uuid.UUID, limit, offset int) ([]Session, error)

	// Count active sessions for a login
	CountActiveByLoginID(ctx context.Context, loginID uuid.UUID) (int, error)

	// Revoke a session by ID
	Revoke(ctx context.Context, id uuid.UUID) error

	// Revoke a session by JTI
	RevokeByJTI(ctx context.Context, jti string) error

	// Revoke all sessions for a login
	RevokeAllByLoginID(ctx context.Context, loginID uuid.UUID) error

	// Revoke all sessions except the current one
	RevokeAllExceptCurrent(ctx context.Context, loginID uuid.UUID, currentSessionID uuid.UUID) error

	// Update last activity timestamp
	UpdateActivity(ctx context.Context, jti string) error

	// Check if a session is revoked
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// Check if a session is valid (not revoked and not expired)
	IsValid(ctx context.Context, jti string) (bool, error)

	// Cleanup expired sessions (for maintenance)
	DeleteExpired(ctx context.Context) error

	// Cleanup old revoked sessions (for maintenance)
	DeleteOldRevoked(ctx context.Context) error
}
