package sessions

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Service provides session management business logic
type Service struct {
	repo Repository
}

// NewService creates a new session service
func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
	}
}

// CreateSession creates a new session record
func (s *Service) CreateSession(ctx context.Context, req CreateSessionRequest) (*Session, error) {
	// Validate request
	if req.LoginID == uuid.Nil {
		return nil, fmt.Errorf("login_id is required")
	}
	if req.JTI == "" {
		return nil, fmt.Errorf("jti is required")
	}
	if req.TokenType != TokenTypeAccess && req.TokenType != TokenTypeRefresh {
		return nil, fmt.Errorf("invalid token_type")
	}
	if req.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}

	return s.repo.Create(ctx, req)
}

// GetSession retrieves a session by ID
func (s *Service) GetSession(ctx context.Context, id uuid.UUID) (*Session, error) {
	return s.repo.GetByID(ctx, id)
}

// GetSessionByJTI retrieves a session by JTI
func (s *Service) GetSessionByJTI(ctx context.Context, jti string) (*Session, error) {
	return s.repo.GetByJTI(ctx, jti)
}

// ListActiveSessions lists all active sessions for a login
func (s *Service) ListActiveSessions(ctx context.Context, loginID uuid.UUID) ([]Session, error) {
	return s.repo.ListActiveByLoginID(ctx, loginID)
}

// ListActiveSessionSummaries returns a simplified view of active sessions
func (s *Service) ListActiveSessionSummaries(ctx context.Context, loginID uuid.UUID, currentJTI string) (*SessionListResponse, error) {
	sessions, err := s.repo.ListActiveByLoginID(ctx, loginID)
	if err != nil {
		return nil, err
	}

	activeCount, err := s.repo.CountActiveByLoginID(ctx, loginID)
	if err != nil {
		return nil, err
	}

	summaries := make([]SessionSummary, len(sessions))
	for i, session := range sessions {
		summaries[i] = SessionSummary{
			ID:               session.ID,
			DeviceName:       session.DeviceName,
			DeviceType:       session.DeviceType,
			IPAddress:        session.IPAddress,
			LastActivity:     session.LastActivity,
			CreatedAt:        session.CreatedAt,
			ExpiresAt:        session.ExpiresAt,
			IsCurrentSession: session.JTI == currentJTI,
			RevokedAt:        session.RevokedAt,
		}
	}

	return &SessionListResponse{
		Sessions:    summaries,
		Total:       len(summaries),
		ActiveCount: activeCount,
		CurrentJTI:  currentJTI,
	}, nil
}

// RevokeSession revokes a specific session
func (s *Service) RevokeSession(ctx context.Context, id uuid.UUID) error {
	return s.repo.Revoke(ctx, id)
}

// RevokeSessionByJTI revokes a session by JTI
func (s *Service) RevokeSessionByJTI(ctx context.Context, jti string) error {
	return s.repo.RevokeByJTI(ctx, jti)
}

// RevokeAllSessions revokes all sessions for a login
func (s *Service) RevokeAllSessions(ctx context.Context, loginID uuid.UUID, exceptCurrent bool, currentSessionID uuid.UUID) error {
	if exceptCurrent && currentSessionID != uuid.Nil {
		return s.repo.RevokeAllExceptCurrent(ctx, loginID, currentSessionID)
	}
	return s.repo.RevokeAllByLoginID(ctx, loginID)
}

// UpdateSessionActivity updates the last activity timestamp for a session
func (s *Service) UpdateSessionActivity(ctx context.Context, jti string) error {
	return s.repo.UpdateActivity(ctx, jti)
}

// IsSessionRevoked checks if a session has been revoked
func (s *Service) IsSessionRevoked(ctx context.Context, jti string) (bool, error) {
	return s.repo.IsRevoked(ctx, jti)
}

// IsSessionValid checks if a session is valid (not revoked and not expired)
func (s *Service) IsSessionValid(ctx context.Context, jti string) (bool, error) {
	return s.repo.IsValid(ctx, jti)
}

// GetSessionStatus returns the status of a session
func (s *Service) GetSessionStatus(ctx context.Context, jti string) (*SessionStatusResponse, error) {
	session, err := s.repo.GetByJTI(ctx, jti)
	if err != nil {
		return nil, err
	}

	isRevoked := session.RevokedAt != nil
	isExpired := session.ExpiresAt.Before(time.Now())
	isValid := !isRevoked && !isExpired

	return &SessionStatusResponse{
		IsValid:   isValid,
		IsRevoked: isRevoked,
		IsExpired: isExpired,
	}, nil
}

// CleanupExpiredSessions removes expired sessions (maintenance task)
func (s *Service) CleanupExpiredSessions(ctx context.Context) error {
	return s.repo.DeleteExpired(ctx)
}

// CleanupOldRevokedSessions removes old revoked sessions (maintenance task)
func (s *Service) CleanupOldRevokedSessions(ctx context.Context) error {
	return s.repo.DeleteOldRevoked(ctx)
}
