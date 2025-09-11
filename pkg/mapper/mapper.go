package mapper

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MappedUser represents a user with mapped fields for compatibility with various systems
type User struct {
	UserId      string                 `json:"user_id,omitempty"`
	LoginID     string                 `json:"login_id,omitempty"`
	DisplayName string                 `json:"display_name,omitempty"`
	ExtraClaims map[string]interface{} `json:"extra_claims,omitempty"`
	UserInfo    UserInfo               `json:"user_info,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
	Groups      []string               `json:"groups,omitempty"`
}

type UserInfo struct {
	Sub                 string    `json:"sub,omitempty"`            // Subject - Identifier for the End-User (required)
	Name                string    `json:"name,omitempty"`           // End-User's full name
	PreferredName       string    `json:"preferred_name,omitempty"` // Name by which the End-User wishes to be referred to
	PreferredUsername   string    `json:"preferred_username,omitempty"`
	Email               string    `json:"email,omitempty"`                 // End-User's preferred e-mail address
	EmailVerified       bool      `json:"email_verified,omitempty"`        // True if email has been verified
	UpdatedAt           time.Time `json:"updated_at,omitempty"`            // Time the information was last updated
	PhoneNumber         string    `json:"phone_number,omitempty"`          // End-User's preferred telephone number
	PhoneNumberVerified bool      `json:"phone_number_verified,omitempty"` // True if phone number has been verified
	Birthdate           string    `json:"birthdate,omitempty"`             // End-User's birthday
}

// DelegatedUserMapper interface for retrieving delegated users
type DelegatedUserMapper interface {
	GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]User, error)
}

// DefaultDelegatedUserMapper provides a default implementation of DelegatedUserMapper
type DefaultDelegatedUserMapper struct{}

// GetDelegatedUsers returns delegated users for a login ID
func (m DefaultDelegatedUserMapper) GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]User, error) {
	return []User{}, nil
}
