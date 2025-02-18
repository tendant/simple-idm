package login

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login/logindb"
)

type MappedUser struct {
	UserId       string
	DisplayName  string
	CustomClaims map[string]interface{}
}

type UserMapper interface {
	GetUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error)
}

type DefaultUserMapper struct {
	queries *logindb.Queries
}

// func NewDefaultUserMapper() *DefaultUserMapper {
// 	return &DefaultUserMapper{}
// }

func NewDefaultUserMapper(queries *logindb.Queries) *DefaultUserMapper {
	return &DefaultUserMapper{
		queries: queries,
	}
}

func (m DefaultUserMapper) GetUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error) {
	// Get users by login UUID
	users, err := m.queries.GetUsersByLoginUuid(ctx, uuid.NullUUID{UUID: loginUuid, Valid: true})
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
		customClaims := map[string]interface{}{
			"email":    user.Email,
			"username": user.Username.String,
			"roles":    strRoles,
		}

		mappedUsers = append(mappedUsers, MappedUser{
			UserId:       user.Uuid.String(),
			DisplayName:  user.Name.String,
			CustomClaims: customClaims,
		})
	}

	return mappedUsers, nil
}

type DelegatedUserMapper interface {
	GetDelegatedUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error)
}

type DefaultDelegatedUserMapper struct{}

func (m DefaultDelegatedUserMapper) GetDelegatedUsers(ctx context.Context, loginUuid uuid.UUID) ([]MappedUser, error) {
	return []MappedUser{}, nil
}
