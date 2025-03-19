package impersonate

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/mapper"
)

// Service implements the DelegatedUserMapper interface
type Service struct {
	usermapper mapper.UserMapper
	repository DelegationRepository
}

// NewService creates a new delegation service that implements DelegatedUserMapper
func NewService(usermapper mapper.UserMapper, repository DelegationRepository) *Service {
	return &Service{
		usermapper: usermapper,
		repository: repository,
	}
}

// GetDelegatedUsers implements the DelegatedUserMapper interface from simple-idm/pkg/mapper
// It retrieves all delegator users for the specified delegatee loginID
func (s *Service) GetDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	if s.repository == nil {
		slog.Warn("Delegation service repository is nil")
		return nil, nil
	}

	// Get delegated users using the repository
	delegatedUsers, err := s.repository.FindDelegatedUsers(ctx, loginID)
	if err != nil {
		return nil, fmt.Errorf("error getting delegated users: %w", err)
	}

	return delegatedUsers, nil
}

// GetOriginalUser retrieves a user by their user ID
func (s *Service) GetOriginalUser(ctx context.Context, userId uuid.UUID) (mapper.User, error) {
	if s.usermapper == nil {
		slog.Warn("Impersonate service usermapper is nil")
		return mapper.User{}, fmt.Errorf("usermapper not available")
	}

	// Find user by login ID
	user, err := s.usermapper.GetUserByUserID(ctx, userId)
	if err != nil {
		return mapper.User{}, fmt.Errorf("error getting user: %w", err)
	}

	return user, nil
}
