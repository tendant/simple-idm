package mapper

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

// Common errors
var (
	ErrUserNotFound = errors.New("user not found")
)

// InMemoryMapperRepository implements MapperRepository using in-memory storage
type InMemoryMapperRepository struct {
	mu    sync.RWMutex
	users map[uuid.UUID]UserEntity // userID -> UserEntity
}

// NewInMemoryMapperRepository creates a new in-memory mapper repository
func NewInMemoryMapperRepository() *InMemoryMapperRepository {
	return &InMemoryMapperRepository{
		users: make(map[uuid.UUID]UserEntity),
	}
}

// AddUser adds a user to the in-memory store (for testing/seeding)
func (r *InMemoryMapperRepository) AddUser(user UserEntity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = user
}

// GetUsersByLoginID retrieves all users linked to a login ID
func (r *InMemoryMapperRepository) GetUsersByLoginID(ctx context.Context, loginID uuid.UUID, includeGroups bool) ([]UserEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []UserEntity
	for _, user := range r.users {
		if user.LoginIDValid && user.LoginID == loginID {
			entity := user
			if !includeGroups {
				entity.Groups = []string{}
			}
			result = append(result, entity)
		}
	}
	return result, nil
}

// GetUserByUserID retrieves a user by user ID
func (r *InMemoryMapperRepository) GetUserByUserID(ctx context.Context, userID uuid.UUID, includeGroups bool) (UserEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[userID]
	if !ok {
		return UserEntity{}, ErrUserNotFound
	}

	if !includeGroups {
		user.Groups = []string{}
	}
	return user, nil
}

// FindUsernamesByEmail retrieves all usernames associated with an email
func (r *InMemoryMapperRepository) FindUsernamesByEmail(ctx context.Context, email string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Note: This returns user names, not login usernames
	// In a real implementation, we'd need access to login data
	var usernames []string
	for _, user := range r.users {
		if user.Email == email && user.NameValid {
			usernames = append(usernames, user.Name)
		}
	}
	return usernames, nil
}
