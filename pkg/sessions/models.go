package sessions

import (
	"time"

	"github.com/google/uuid"
)

// TokenType represents the type of token for a session
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// Session represents an active authentication session
type Session struct {
	ID                uuid.UUID  `json:"id"`
	LoginID           uuid.UUID  `json:"login_id"`
	JTI               string     `json:"jti"` // JWT ID
	TokenType         TokenType  `json:"token_type"`
	IssuedAt          time.Time  `json:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	IPAddress         string     `json:"ip_address,omitempty"`
	UserAgent         string     `json:"user_agent,omitempty"`
	DeviceFingerprint string     `json:"device_fingerprint,omitempty"`
	DeviceName        string     `json:"device_name,omitempty"`
	DeviceType        string     `json:"device_type,omitempty"`
	LastActivity      time.Time  `json:"last_activity"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// SessionSummary is a simplified session view for listing
type SessionSummary struct {
	ID                uuid.UUID  `json:"id"`
	DeviceName        string     `json:"device_name"`
	DeviceType        string     `json:"device_type"`
	IPAddress         string     `json:"ip_address"`
	LastActivity      time.Time  `json:"last_activity"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	IsCurrentSession  bool       `json:"is_current_session"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// CreateSessionRequest represents the request to create a new session
type CreateSessionRequest struct {
	LoginID           uuid.UUID `json:"login_id"`
	JTI               string    `json:"jti"`
	TokenType         TokenType `json:"token_type"`
	ExpiresAt         time.Time `json:"expires_at"`
	IPAddress         string    `json:"ip_address,omitempty"`
	UserAgent         string    `json:"user_agent,omitempty"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	DeviceName        string    `json:"device_name,omitempty"`
	DeviceType        string    `json:"device_type,omitempty"`
}

// SessionListResponse represents the response for listing sessions
type SessionListResponse struct {
	Sessions      []SessionSummary `json:"sessions"`
	Total         int              `json:"total"`
	ActiveCount   int              `json:"active_count"`
	CurrentJTI    string           `json:"current_jti,omitempty"`
}

// RevokeSessionRequest represents the request to revoke a session
type RevokeSessionRequest struct {
	SessionID uuid.UUID `json:"session_id"`
}

// RevokeAllSessionsRequest represents the request to revoke all sessions
type RevokeAllSessionsRequest struct {
	ExceptCurrentSession bool `json:"except_current_session"`
}

// SessionStatusResponse represents the status of a session
type SessionStatusResponse struct {
	IsValid  bool `json:"is_valid"`
	IsRevoked bool `json:"is_revoked"`
	IsExpired bool `json:"is_expired"`
}
