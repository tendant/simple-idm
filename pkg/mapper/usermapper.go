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
			"email":    user.Email,
			"username": "", // Placeholder for username
			"roles":    strRoles,
		}

		mappedUsers = append(mappedUsers, User{
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
		"email":    user.Email,
		"username": "", // Placeholder for username
		"roles":    strRoles,
	}

	return User{
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
