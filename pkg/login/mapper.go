package login

import (
	"context"

	"github.com/google/uuid"
)

type MappedUser struct {
	UserId       string
	DisplayName  string
	TenantId     string
	CustomClaims map[string]interface{}
}

type UserMapper interface {
	GetUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error)
}

type DefaultUserMapper struct{}

// func NewDefaultUserMapper() *DefaultUserMapper {
// 	return &DefaultUserMapper{}
// }

func (m DefaultUserMapper) GetUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error) {
	// For now, return a single mapped user with the login UUID
	// Once the login_uuid column is added to users table, we can query for actual users
	return []MappedUser{
		{
			UserId:       loginUuid.String(),
			DisplayName:  "", // Will be populated from users table
			TenantId:     "", // Will be populated based on tenant info
			CustomClaims: make(map[string]interface{}),
		},
	}, nil
}

type DelegatedUserMapper interface {
	GetDelegatedUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error)
}

type DefaultDelegatedUserMapper struct{}

func (m DefaultDelegatedUserMapper) GetDelegatedUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error) {
	return []MappedUser{}, nil
}
