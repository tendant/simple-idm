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

type DelegatedUserMapper interface {
	GetDelegatedUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error)
}
