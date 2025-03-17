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
	GetUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error)
	GetUserByUserID(ctx context.Context, userID uuid.UUID) (MappedUser, error)
	FindUsernamesByEmail(ctx context.Context, email string) ([]string, error)
}

// DefaultUserMapper implements the UserMapper interface
type DefaultUserMapper struct {
	queries *mapperdb.Queries
}

// NewUserMapper creates a new DefaultUserMapper with the given repository
func NewUserMapper(queries *mapperdb.Queries) *DefaultUserMapper {
	return &DefaultUserMapper{
		queries: queries,
	}
}

// FindUsersByLoginID delegates to the repository
// func (m *DefaultUserMapper) GetUsers(ctx context.Context, loginID uuid.UUID) ([]User, error) {
// 	if m.repository != nil {
// 		return m.repository.GetUsers(ctx, loginID)
// 	}
// 	// Fallback implementation using queries if repository is not set
// 	return nil, fmt.Errorf("repository not set")
// }

// GetUserByUserID delegates to the repository
func (m *DefaultUserMapper) GetUserByUserID(ctx context.Context, userID uuid.UUID) (MappedUser, error) {
	if m.queries == nil {
		slog.Warn("DefaultUserRepository queries is nil")
		return MappedUser{}, fmt.Errorf("queries not initialized")
	}

	user, err := m.queries.GetUserById(ctx, userID)
	if err != nil {
		return MappedUser{}, fmt.Errorf("error getting user: %w", err)
	}

	// Convert roles from interface{} to []string
	roles, ok := user.Roles.([]interface{})
	if !ok {
		return MappedUser{}, fmt.Errorf("invalid roles format")
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
		"username": "", // Placeholder for username
		"roles":    strRoles,
	}

	return MappedUser{
		UserId:      user.ID.String(),
		LoginID:     "", // This would need to be populated from a separate query
		Email:       user.Email,
		DisplayName: user.Name.String,
		ExtraClaims: extraClaims,
		Roles:       strRoles, // Assuming first role is primary
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

// GetUsers implements the original UserMapper method
func (m *DefaultUserMapper) GetUsers(ctx context.Context, loginID uuid.UUID) ([]MappedUser, error) {
	if m.queries == nil {
		slog.Warn("DefaultUserRepository queries is nil")
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
			"username": "", // Placeholder for username
			"roles":    strRoles,
		}

		mappedUsers = append(mappedUsers, MappedUser{
			UserId:      user.ID.String(),
			LoginID:     loginID.String(),
			Email:       user.Email,
			DisplayName: user.Name.String,
			ExtraClaims: extraClaims,
			Roles:       strRoles, // Assuming first role is primary
		})
	}

	return mappedUsers, nil
}
