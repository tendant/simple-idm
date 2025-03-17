package mapper

import (
	"context"

	"github.com/google/uuid"
)

// MappedUser represents a user with mapped fields for compatibility with various systems
type MappedUser struct {
	UserId      string                 `json:"user_id,omitempty"`
	LoginID     string                 `json:"login_id,omitempty"`
	Email       string                 `json:"email,omitempty"`
	DisplayName string                 `json:"display_name,omitempty"`
	ExtraClaims map[string]interface{} `json:"extra_claims,omitempty"`
	// TenantUuid  uuid.UUID              `json:"tenant_uuid,omitempty"`
	// DeptUuid    uuid.UUID              `json:"dept_uuid,omitempty"`
	// TenantName  string                 `json:"tenant_name,omitempty"`
	// DeptName    string                 `json:"dept_name,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// DelegatedUserMapper interface for retrieving delegated users
type DelegatedUserMapper interface {
	GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error)
}

// DefaultDelegatedUserMapper provides a default implementation of DelegatedUserMapper
type DefaultDelegatedUserMapper struct{}

// GetDelegatedUsers returns delegated users for a login ID
func (m DefaultDelegatedUserMapper) GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error) {
	return []MappedUser{}, nil
}
