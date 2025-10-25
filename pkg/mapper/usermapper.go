package mapper

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
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
	repo MapperRepository
}

// NewDefaultUserMapper creates a new DefaultUserMapper with the given repository
func NewDefaultUserMapper(repo MapperRepository) *DefaultUserMapper {
	return &DefaultUserMapper{
		repo: repo,
	}
}

// FindUsersByLoginID implements the original UserMapper method
func (m *DefaultUserMapper) FindUsersByLoginID(ctx context.Context, loginID uuid.UUID) ([]User, error) {
	if m.repo == nil {
		slog.Warn("DefaultUserMapper repo is nil")
		return nil, nil
	}

	// Try to get users with groups first, fallback to without groups if needed
	userEntities, err := m.repo.GetUsersByLoginID(ctx, loginID, true)
	if err != nil {
		// Fallback to query without groups
		slog.Warn("Falling back to query without groups", "error", err)
		userEntities, err = m.repo.GetUsersByLoginID(ctx, loginID, false)
		if err != nil {
			return nil, fmt.Errorf("error getting users: %w", err)
		}
	}

	// Convert UserEntity to User
	mappedUsers := make([]User, 0, len(userEntities))
	for _, entity := range userEntities {
		// Create custom claims
		extraClaims := map[string]interface{}{
			"username": "", // Placeholder for username
			"roles":    entity.Roles,
			"groups":   entity.Groups,
		}

		phoneNumber := ""
		if entity.PhoneValid {
			phoneNumber = entity.Phone
		}

		displayName := ""
		if entity.NameValid {
			displayName = entity.Name
		}

		userInfo := UserInfo{
			Email: entity.Email,
			// FIX-ME: need to add email verification flow in the future
			EmailVerified: true,
			PhoneNumber:   phoneNumber,
		}

		mappedUsers = append(mappedUsers, User{
			UserId:      entity.ID.String(),
			LoginID:     loginID.String(),
			UserInfo:    userInfo,
			DisplayName: displayName,
			ExtraClaims: extraClaims,
			Roles:       entity.Roles,
			Groups:      entity.Groups,
		})
	}

	return mappedUsers, nil
}

// GetUserByUserID delegates to the repository
func (m *DefaultUserMapper) GetUserByUserID(ctx context.Context, userID uuid.UUID) (User, error) {
	if m.repo == nil {
		slog.Warn("DefaultUserMapper repo is nil")
		return User{}, fmt.Errorf("repo not initialized")
	}

	// Try to get user with groups first, fallback to without groups if needed
	entity, err := m.repo.GetUserByUserID(ctx, userID, true)
	if err != nil {
		slog.Warn("Falling back to query without groups", "error", err)
		// Fallback to query without groups
		entity, err = m.repo.GetUserByUserID(ctx, userID, false)
		if err != nil {
			return User{}, fmt.Errorf("error getting user: %w", err)
		}
	}

	// Create custom claims
	extraClaims := map[string]interface{}{
		"username": "", // Placeholder for username
		"roles":    entity.Roles,
		"groups":   entity.Groups,
	}

	displayName := ""
	if entity.NameValid {
		displayName = entity.Name
	}

	phoneNumber := ""
	if entity.PhoneValid {
		phoneNumber = entity.Phone
	}

	loginID := ""
	if entity.LoginIDValid {
		loginID = entity.LoginID.String()
	}

	userInfo := UserInfo{
		Email: entity.Email,
		// FIX-ME: need to add email verification flow in the future
		EmailVerified: true,
		PhoneNumber:   phoneNumber,
	}

	return User{
		UserId:      entity.ID.String(),
		LoginID:     loginID,
		DisplayName: displayName,
		ExtraClaims: extraClaims,
		UserInfo:    userInfo,
		Roles:       entity.Roles,
		Groups:      entity.Groups,
	}, nil
}

// FindUsernamesByEmail delegates to the repository
func (m *DefaultUserMapper) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	if m.repo == nil {
		slog.Warn("DefaultUserMapper repo is nil")
		return nil, fmt.Errorf("repo not initialized")
	}

	usernames, err := m.repo.FindUsernamesByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("error finding usernames: %w", err)
	}

	slog.Info("Found usernames by email", "usernames", usernames)

	return usernames, nil
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
