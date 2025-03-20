package mapper

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	mapperdb "github.com/tendant/simple-idm/pkg/mapper/mapperdb"
)

// UserMapper interface combines user mapping and repository operations
type UserMapper interface {
	FindUsersByLoginID(ctx context.Context, loginID uuid.UUID) ([]User, error)
	GetUserByUserID(ctx context.Context, userID uuid.UUID) (User, error)
	FindUsernamesByEmail(ctx context.Context, email string) ([]string, error)
	//TODO: add convertion to claim
	ToTokenClaims(user User) (rootModifications map[string]interface{}, extraClaims map[string]interface{})
}

// DefaultUserMapper implements the UserMapper interface
type DefaultUserMapper struct {
	queries *mapperdb.Queries
}

// NewUserMapper creates a new DefaultUserMapper with the given repository
func NewDefaultUserMapper(queries *mapperdb.Queries) *DefaultUserMapper {
	return &DefaultUserMapper{
		queries: queries,
	}
}

// GetUsers implements the original UserMapper method
func (m *DefaultUserMapper) FindUsersByLoginID(ctx context.Context, loginID uuid.UUID) ([]User, error) {
	if m.queries == nil {
		slog.Warn("DefaultUserRepository queries is nil")
		return nil, nil
	}

	users, err := m.queries.GetUsersByLoginId(ctx, uuid.NullUUID{UUID: loginID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("error getting users: %w", err)
	}

	// Map users to MappedUser
	mappedUsers := make([]User, 0, len(users))
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
			"username": "", // Placeholder for username
			"roles":    strRoles,
		}

		userInfo := UserInfo{
			Email: user.Email,
		}

		mappedUsers = append(mappedUsers, User{
			UserId:      user.ID.String(),
			LoginID:     loginID.String(),
			UserInfo:    userInfo,
			DisplayName: user.Name.String,
			ExtraClaims: extraClaims,
			Roles:       strRoles,
		})
	}

	return mappedUsers, nil
}

// GetUserByUserID delegates to the repository
func (m *DefaultUserMapper) GetUserByUserID(ctx context.Context, userID uuid.UUID) (User, error) {
	if m.queries == nil {
		slog.Warn("DefaultUserRepository queries is nil")
		return User{}, fmt.Errorf("queries not initialized")
	}

	user, err := m.queries.GetUserById(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("error getting user: %w", err)
	}

	// Convert roles from interface{} to []string
	roles, ok := user.Roles.([]interface{})
	if !ok {
		return User{}, fmt.Errorf("invalid roles format")
	}

	strRoles := make([]string, 0, len(roles))
	for _, r := range roles {
		if str, ok := r.(string); ok {
			strRoles = append(strRoles, str)
		}
	}

	// Create custom claims
	extraClaims := map[string]interface{}{
		"username": "", // Placeholder for username
		"roles":    strRoles,
	}

	userInfo := UserInfo{
		Email: user.Email,
	}

	return User{
		UserId:      user.ID.String(),
		LoginID:     "", // This would need to be populated from a separate query
		DisplayName: user.Name.String,
		ExtraClaims: extraClaims,
		UserInfo:    userInfo,
		Roles:       strRoles,
	}, nil
}

// FindUsernamesByEmail delegates to the repository
func (m *DefaultUserMapper) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	if m.queries == nil {
		slog.Warn("DefaultUserRepository queries is nil")
		return nil, fmt.Errorf("queries not initialized")
	}

	// This would need to be implemented based on your database schema
	// For now, returning a placeholder implementation
	return []string{}, nil
}

// ToTokenClaims converts a User to rootModifications and extraClaims maps for token generation
func (m *DefaultUserMapper) ToTokenClaims(user User) (rootModifications map[string]interface{}, extraClaims map[string]interface{}) {
	// Root modifications are applied to the top level of the JWT claims
	rootModifications = map[string]interface{}{}

	// Extra claims should match the exact structure of the User object
	extraClaims = map[string]interface{}{
		"user_id":      user.UserId,
		"login_id":     user.LoginID,
		"display_name": user.DisplayName,
		"roles":        user.Roles,
		"user_info":    user.UserInfo,
	}

	// Add extra_claims as a nested field within extraClaims
	if user.ExtraClaims != nil {
		extraClaims["extra_claims"] = user.ExtraClaims
	} else {
		extraClaims["extra_claims"] = map[string]interface{}{}
	}

	return
}
