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
	// ExtractTokenClaims extracts claims from a token and adds them to the user's extra claims
	ExtractTokenClaims(user User, claims map[string]interface{}) User
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

	// Try to use the new query that includes groups, fallback to old query if not available
	usersWithGroups, err := m.queries.GetUsersByLoginIdWithGroups(ctx, uuid.NullUUID{UUID: loginID, Valid: true})
	if err != nil {
		// Fallback to old query for backward compatibility
		slog.Warn("Falling back to old GetUsersByLoginId query, groups will be empty", "error", err)
		users, err := m.queries.GetUsersByLoginId(ctx, uuid.NullUUID{UUID: loginID, Valid: true})
		if err != nil {
			return nil, fmt.Errorf("error getting users: %w", err)
		}

		// Map users to MappedUser (without groups)
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
				"groups":   []string{}, // Empty groups for backward compatibility
			}

			userInfo := UserInfo{
				Email: user.Email,
				// FIX-ME: need to add email verification flow in the future
				EmailVerified: true,
				PhoneNumber:   user.Phone.String,
			}

			mappedUsers = append(mappedUsers, User{
				UserId:      user.ID.String(),
				LoginID:     loginID.String(),
				UserInfo:    userInfo,
				DisplayName: user.Name.String,
				ExtraClaims: extraClaims,
				Roles:       strRoles,
				Groups:      []string{}, // Empty groups for backward compatibility
			})
		}

		return mappedUsers, nil
	}

	// Map users to MappedUser (with groups)
	mappedUsers := make([]User, 0, len(usersWithGroups))
	for _, user := range usersWithGroups {
		// Convert groups from interface{} to []string
		groups, ok := user.Groups.([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid groups format")
		}

		strGroups := make([]string, 0, len(groups))
		for _, g := range groups {
			if str, ok := g.(string); ok {
				strGroups = append(strGroups, str)
			}
		}

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
			"groups":   strGroups,
		}

		userInfo := UserInfo{
			Email: user.Email,
			// FIX-ME: need to add email verification flow in the future
			EmailVerified: true,
			PhoneNumber:   user.Phone.String,
		}

		mappedUsers = append(mappedUsers, User{
			UserId:      user.ID.String(),
			LoginID:     loginID.String(),
			UserInfo:    userInfo,
			DisplayName: user.Name.String,
			ExtraClaims: extraClaims,
			Roles:       strRoles,
			Groups:      strGroups,
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

	// Try to use the new query that includes groups, fallback to old query if not available
	userWithGroups, err := m.queries.GetUserWithGroupsAndRoles(ctx, userID)
	if err != nil {
		slog.Warn("Falling back to old GetUsersByLoginId query, groups will be empty", "error", err)
		// Fallback to old query for backward compatibility
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
			// FIX-ME: need to add email verification flow in the future
			EmailVerified: true,
		}

		return User{
			UserId:      user.ID.String(),
			LoginID:     user.LoginID.UUID.String(),
			DisplayName: user.Name.String,
			ExtraClaims: extraClaims,
			UserInfo:    userInfo,
			Roles:       strRoles,
			Groups:      []string{}, // Empty groups for backward compatibility
		}, nil
	}

	// Convert groups from interface{} to []string
	groups, ok := userWithGroups.Groups.([]interface{})
	if !ok {
		return User{}, fmt.Errorf("invalid groups format")
	}

	strGroups := make([]string, 0, len(groups))
	for _, g := range groups {
		if str, ok := g.(string); ok {
			strGroups = append(strGroups, str)
		}
	}

	// Convert roles from interface{} to []string
	roles, ok := userWithGroups.Roles.([]interface{})
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
		"groups":   strGroups,
	}

	userInfo := UserInfo{
		Email: userWithGroups.Email,
		// FIX-ME: need to add email verification flow in the future
		EmailVerified: true,
	}

	return User{
		UserId:      userWithGroups.ID.String(),
		LoginID:     userWithGroups.LoginID.UUID.String(),
		DisplayName: userWithGroups.Name.String,
		ExtraClaims: extraClaims,
		UserInfo:    userInfo,
		Roles:       strRoles,
		Groups:      strGroups,
	}, nil
}

// FindUsernamesByEmail delegates to the repository
func (m *DefaultUserMapper) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	if m.queries == nil {
		slog.Warn("DefaultUserRepository queries is nil")
		return nil, fmt.Errorf("queries not initialized")
	}

	usernames, err := m.queries.FindUsernamesByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("error finding usernames: %w", err)
	}

	var res []string
	for _, username := range usernames {
		if username.Valid {
			res = append(res, username.String)
		}
	}

	slog.Info("Found usernames by email", "usernames", res)

	return res, nil
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
		"groups":       user.Groups,
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

// ExtractTokenClaims extracts claims from a token and adds them to the user's extra claims
func (m *DefaultUserMapper) ExtractTokenClaims(user User, claims map[string]interface{}) User {
	// Initialize extra claims map if it doesn't exist
	if user.ExtraClaims == nil {
		user.ExtraClaims = make(map[string]interface{})
	}

	slog.Info("Extracting token claims", "claims", claims)

	// Copy claims that don't already exist in the user's extra claims
	if claims["extra_claims"] != nil {
		extraClaims := claims["extra_claims"].(map[string]interface{})
		if extraClaims["extra_claims"] != nil {
			extraClaims = extraClaims["extra_claims"].(map[string]interface{})
			for key, claim := range extraClaims {
				if user.ExtraClaims[key] == nil {
					user.ExtraClaims[key] = claim
				}
			}
		}
	}
	return user
}
