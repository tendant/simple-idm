package mapper

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	mapperdb "github.com/tendant/simple-idm/pkg/mapper/mapperdb"
)

type MappedUser struct {
	UserId      string                 `json:"user_id,omitempty"`
	LoginID     string                 `json:"login_id,omitempty"`
	Email       string                 `json:"email,omitempty"`
	DisplayName string                 `json:"display_name,omitempty"`
	ExtraClaims map[string]interface{} `json:"extra_claims,omitempty"`
	TenantUuid  uuid.UUID              `json:"tenant_uuid,omitempty"`
	DeptUuid    uuid.UUID              `json:"dept_uuid,omitempty"`
	TenantName  string                 `json:"tenant_name,omitempty"`
	DeptName    string                 `json:"dept_name,omitempty"`
	Role        string                 `json:"role,omitempty"`
}

type UserMapper interface {
	GetUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error)
}

type DefaultUserMapper struct {
	queries *mapperdb.Queries
}

// func NewDefaultUserMapper() *DefaultUserMapper {
// 	return &DefaultUserMapper{}
// }

func NewDefaultUserMapper(queries *mapperdb.Queries) *DefaultUserMapper {
	return &DefaultUserMapper{
		queries: queries,
	}
}

func (m DefaultUserMapper) GetUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error) {
	// Get users by login ID
	if m.queries == nil {
		slog.Warn("DefaultUserMapper queries is nil")
		return nil, nil
	}
	users, err := m.queries.GetUsersByLoginId(ctx, uuid.NullUUID{UUID: loginID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("error getting users: %w", err)
	}

	// Map users to MappedUser
	mappedUsers := make([]MappedUser, 0, len(users))
	for _, user := range users {
		// Convert roles from interface{} to []string
		roles, ok := user.Roles.([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid roles format")
		}

		strRoles := make([]string, 0, len(roles))
		for _, r := range roles {
			if str, ok := r.(string); ok {
				strRoles = append(strRoles, str)
			}
		}

		// Create custom claims
		extraClaims := map[string]interface{}{
			"email":    user.Email,
			"username": "", // Removed user.Username reference as it doesn't exist
			"roles":    strRoles,
		}

		mappedUsers = append(mappedUsers, MappedUser{
			UserId:      user.ID.String(),
			LoginID:     loginID.String(),
			Email:       user.Email,
			DisplayName: user.Name.String,
			ExtraClaims: extraClaims,
		})
	}

	return mappedUsers, nil
}

type DelegatedUserMapper interface {
	GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error)
}

type DefaultDelegatedUserMapper struct{}

func (m DefaultDelegatedUserMapper) GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error) {
	return []MappedUser{}, nil
}
