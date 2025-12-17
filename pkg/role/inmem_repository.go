package role

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InMemoryRoleRepository implements RoleRepository using in-memory storage
type InMemoryRoleRepository struct {
	mu        sync.RWMutex
	roles     map[uuid.UUID]Role            // roleID -> Role
	userRoles map[uuid.UUID][]uuid.UUID     // roleID -> []userID
	roleUsers map[uuid.UUID]map[uuid.UUID]RoleUser // roleID -> userID -> RoleUser
}

// NewInMemoryRoleRepository creates a new in-memory role repository
func NewInMemoryRoleRepository() *InMemoryRoleRepository {
	return &InMemoryRoleRepository{
		roles:     make(map[uuid.UUID]Role),
		userRoles: make(map[uuid.UUID][]uuid.UUID),
		roleUsers: make(map[uuid.UUID]map[uuid.UUID]RoleUser),
	}
}

// FindRoles returns all roles
func (r *InMemoryRoleRepository) FindRoles(ctx context.Context) ([]Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	roles := make([]Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

// CreateRole creates a new role
func (r *InMemoryRoleRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := uuid.New()
	r.roles[id] = Role{ID: id, Name: name}
	r.userRoles[id] = []uuid.UUID{}
	r.roleUsers[id] = make(map[uuid.UUID]RoleUser)
	return id, nil
}

// UpdateRole updates an existing role
func (r *InMemoryRoleRepository) UpdateRole(ctx context.Context, arg UpdateRoleParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.roles[arg.ID]; !ok {
		return ErrRoleNotFound
	}
	r.roles[arg.ID] = Role{ID: arg.ID, Name: arg.Name}
	return nil
}

// DeleteRole deletes a role
func (r *InMemoryRoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.roles, id)
	delete(r.userRoles, id)
	delete(r.roleUsers, id)
	return nil
}

// GetRoleById retrieves a role by ID
func (r *InMemoryRoleRepository) GetRoleById(ctx context.Context, id uuid.UUID) (Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	role, ok := r.roles[id]
	if !ok {
		return Role{}, ErrRoleNotFound
	}
	return role, nil
}

// GetRoleIdByName retrieves a role ID by name
func (r *InMemoryRoleRepository) GetRoleIdByName(ctx context.Context, name string) (uuid.UUID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, role := range r.roles {
		if role.Name == name {
			return role.ID, nil
		}
	}
	return uuid.Nil, ErrRoleNotFound
}

// GetRoleUsers retrieves users assigned to a role
func (r *InMemoryRoleRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]RoleUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	users, ok := r.roleUsers[roleID]
	if !ok {
		return []RoleUser{}, nil
	}

	result := make([]RoleUser, 0, len(users))
	for _, user := range users {
		result = append(result, user)
	}
	return result, nil
}

// HasUsers checks if a role has users assigned
func (r *InMemoryRoleRepository) HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	users, ok := r.roleUsers[roleID]
	if !ok {
		return false, nil
	}
	return len(users) > 0, nil
}

// RemoveUserFromRole removes a user from a role
func (r *InMemoryRoleRepository) RemoveUserFromRole(ctx context.Context, arg RemoveUserFromRoleParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if users, ok := r.roleUsers[arg.RoleID]; ok {
		delete(users, arg.UserID)
	}

	// Also update userRoles slice
	if userIDs, ok := r.userRoles[arg.RoleID]; ok {
		newUserIDs := make([]uuid.UUID, 0, len(userIDs))
		for _, uid := range userIDs {
			if uid != arg.UserID {
				newUserIDs = append(newUserIDs, uid)
			}
		}
		r.userRoles[arg.RoleID] = newUserIDs
	}

	return nil
}

// AddUserToRole adds a user to a role
func (r *InMemoryRoleRepository) AddUserToRole(ctx context.Context, roleID, userID uuid.UUID, username string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.roles[roleID]; !ok {
		return ErrRoleNotFound
	}

	// Initialize maps if needed
	if r.roleUsers[roleID] == nil {
		r.roleUsers[roleID] = make(map[uuid.UUID]RoleUser)
	}

	r.roleUsers[roleID][userID] = RoleUser{
		ID:        userID,
		Name:      username,
		NameValid: username != "",
	}

	// Also update userRoles slice
	r.userRoles[roleID] = append(r.userRoles[roleID], userID)

	return nil
}

// WithTx returns the same repository (no-op for in-memory)
func (r *InMemoryRoleRepository) WithTx(tx interface{}) RoleRepository {
	return r
}

// WithPgxTx returns the same repository (no-op for in-memory)
func (r *InMemoryRoleRepository) WithPgxTx(tx pgx.Tx) RoleRepository {
	return r
}

// SeedRole adds a role directly (for testing/initialization)
func (r *InMemoryRoleRepository) SeedRole(role Role) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.ID] = role
	if r.userRoles[role.ID] == nil {
		r.userRoles[role.ID] = []uuid.UUID{}
	}
	if r.roleUsers[role.ID] == nil {
		r.roleUsers[role.ID] = make(map[uuid.UUID]RoleUser)
	}
}
