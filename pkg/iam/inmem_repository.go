package iam

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Common errors
var (
	ErrUserNotFound  = errors.New("user not found")
	ErrRoleNotFound  = errors.New("role not found")
	ErrGroupNotFound = errors.New("group not found")
)

// InMemoryIamRepository implements IamRepository using in-memory storage
type InMemoryIamRepository struct {
	mu        sync.RWMutex
	users     map[uuid.UUID]User
	roles     map[uuid.UUID]Role
	userRoles map[uuid.UUID][]uuid.UUID // userID -> []roleID
}

// NewInMemoryIamRepository creates a new in-memory IAM repository
func NewInMemoryIamRepository() *InMemoryIamRepository {
	return &InMemoryIamRepository{
		users:     make(map[uuid.UUID]User),
		roles:     make(map[uuid.UUID]Role),
		userRoles: make(map[uuid.UUID][]uuid.UUID),
	}
}

// CreateUser creates a new user
func (r *InMemoryIamRepository) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	user := User{
		ID:             uuid.New(),
		Email:          params.Email,
		Name:           params.Name,
		LoginID:        params.LoginID,
		CreatedAt:      now,
		LastModifiedAt: now,
	}

	r.users[user.ID] = user
	r.userRoles[user.ID] = []uuid.UUID{}
	return user, nil
}

// GetUserWithRoles gets a user with their roles
func (r *InMemoryIamRepository) GetUserWithRoles(ctx context.Context, id uuid.UUID) (UserWithRoles, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[id]
	if !ok || user.DeletedAt != nil {
		return UserWithRoles{}, ErrUserNotFound
	}

	// Get roles for user
	roleIDs := r.userRoles[id]
	roles := make([]Role, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		if role, ok := r.roles[roleID]; ok {
			roles = append(roles, role)
		}
	}

	return UserWithRoles{
		User:  user,
		Roles: roles,
	}, nil
}

// FindUsersWithRoles finds all users with their roles
func (r *InMemoryIamRepository) FindUsersWithRoles(ctx context.Context) ([]UserWithRoles, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []UserWithRoles
	for _, user := range r.users {
		if user.DeletedAt != nil {
			continue
		}

		roleIDs := r.userRoles[user.ID]
		roles := make([]Role, 0, len(roleIDs))
		for _, roleID := range roleIDs {
			if role, ok := r.roles[roleID]; ok {
				roles = append(roles, role)
			}
		}

		result = append(result, UserWithRoles{
			User:  user,
			Roles: roles,
		})
	}
	return result, nil
}

// UpdateUser updates a user
func (r *InMemoryIamRepository) UpdateUser(ctx context.Context, params UpdateUserParams) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, ok := r.users[params.ID]
	if !ok || user.DeletedAt != nil {
		return User{}, ErrUserNotFound
	}

	user.Name = params.Name
	user.LastModifiedAt = time.Now()
	r.users[params.ID] = user
	return user, nil
}

// UpdateUserLoginID updates a user's login ID
func (r *InMemoryIamRepository) UpdateUserLoginID(ctx context.Context, userID uuid.UUID, loginID *uuid.UUID) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, ok := r.users[userID]
	if !ok || user.DeletedAt != nil {
		return User{}, ErrUserNotFound
	}

	user.LoginID = loginID
	user.LastModifiedAt = time.Now()
	r.users[userID] = user
	return user, nil
}

// DeleteUser deletes a user (soft delete)
func (r *InMemoryIamRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, ok := r.users[id]
	if !ok {
		return nil // Idempotent delete
	}

	now := time.Now()
	user.DeletedAt = &now
	r.users[id] = user
	return nil
}

// DeleteUserRoles deletes all roles for a user
func (r *InMemoryIamRepository) DeleteUserRoles(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.userRoles[userID] = []uuid.UUID{}
	return nil
}

// AnyUserExists checks if any user exists in the system
func (r *InMemoryIamRepository) AnyUserExists(ctx context.Context) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.DeletedAt == nil {
			return true, nil
		}
	}
	return false, nil
}

// CreateUserRole creates a user-role association
func (r *InMemoryIamRepository) CreateUserRole(ctx context.Context, params UserRoleParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if user exists
	if _, ok := r.users[params.UserID]; !ok {
		return ErrUserNotFound
	}

	// Check if role exists
	if _, ok := r.roles[params.RoleID]; !ok {
		return ErrRoleNotFound
	}

	// Add role to user (avoid duplicates)
	roles := r.userRoles[params.UserID]
	for _, roleID := range roles {
		if roleID == params.RoleID {
			return nil // Already assigned
		}
	}
	r.userRoles[params.UserID] = append(roles, params.RoleID)
	return nil
}

// FindRoles returns all roles
func (r *InMemoryIamRepository) FindRoles(ctx context.Context) ([]Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	roles := make([]Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

// CreateRole creates a new role
func (r *InMemoryIamRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := uuid.New()
	r.roles[id] = Role{ID: id, Name: name}
	return id, nil
}

// SeedUser adds a user directly (for testing/initialization)
func (r *InMemoryIamRepository) SeedUser(user User) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = user
	if r.userRoles[user.ID] == nil {
		r.userRoles[user.ID] = []uuid.UUID{}
	}
}

// SeedRole adds a role directly (for testing/initialization)
func (r *InMemoryIamRepository) SeedRole(role Role) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.ID] = role
}

// InMemoryIamGroupRepository implements IamGroupRepository using in-memory storage
type InMemoryIamGroupRepository struct {
	mu         sync.RWMutex
	groups     map[uuid.UUID]Group
	userGroups map[uuid.UUID][]uuid.UUID // userID -> []groupID
	groupUsers map[uuid.UUID][]uuid.UUID // groupID -> []userID
}

// NewInMemoryIamGroupRepository creates a new in-memory IAM group repository
func NewInMemoryIamGroupRepository() *InMemoryIamGroupRepository {
	return &InMemoryIamGroupRepository{
		groups:     make(map[uuid.UUID]Group),
		userGroups: make(map[uuid.UUID][]uuid.UUID),
		groupUsers: make(map[uuid.UUID][]uuid.UUID),
	}
}

// CreateGroup creates a new group
func (r *InMemoryIamGroupRepository) CreateGroup(ctx context.Context, params CreateGroupParams) (Group, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	group := Group{
		ID:          uuid.New(),
		Name:        params.Name,
		Description: params.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	r.groups[group.ID] = group
	r.groupUsers[group.ID] = []uuid.UUID{}
	return group, nil
}

// GetGroup gets a group by ID
func (r *InMemoryIamGroupRepository) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	group, ok := r.groups[id]
	if !ok || group.DeletedAt != nil {
		return Group{}, ErrGroupNotFound
	}
	return group, nil
}

// FindGroups finds all groups
func (r *InMemoryIamGroupRepository) FindGroups(ctx context.Context) ([]Group, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Group
	for _, group := range r.groups {
		if group.DeletedAt == nil {
			result = append(result, group)
		}
	}
	return result, nil
}

// UpdateGroup updates a group
func (r *InMemoryIamGroupRepository) UpdateGroup(ctx context.Context, params UpdateGroupParams) (Group, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	group, ok := r.groups[params.ID]
	if !ok || group.DeletedAt != nil {
		return Group{}, ErrGroupNotFound
	}

	group.Name = params.Name
	group.Description = params.Description
	group.UpdatedAt = time.Now()
	r.groups[params.ID] = group
	return group, nil
}

// DeleteGroup deletes a group (soft delete)
func (r *InMemoryIamGroupRepository) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	group, ok := r.groups[id]
	if !ok {
		return nil
	}

	now := time.Now()
	group.DeletedAt = &now
	r.groups[id] = group
	return nil
}

// FindGroupUsers finds all users in a group
func (r *InMemoryIamGroupRepository) FindGroupUsers(ctx context.Context, groupID uuid.UUID) ([]User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// This would need access to users - for now return empty
	// In a real implementation, this would need a reference to the user repository
	return []User{}, nil
}

// CreateUserGroup creates a user-group association
func (r *InMemoryIamGroupRepository) CreateUserGroup(ctx context.Context, params UserGroupParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Add group to user
	r.userGroups[params.UserID] = append(r.userGroups[params.UserID], params.GroupID)
	// Add user to group
	r.groupUsers[params.GroupID] = append(r.groupUsers[params.GroupID], params.UserID)
	return nil
}

// UpsertUserGroup creates or reactivates a user-group association
func (r *InMemoryIamGroupRepository) UpsertUserGroup(ctx context.Context, params UserGroupParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already exists
	for _, gid := range r.userGroups[params.UserID] {
		if gid == params.GroupID {
			return nil // Already exists
		}
	}

	// Add group to user
	r.userGroups[params.UserID] = append(r.userGroups[params.UserID], params.GroupID)
	// Add user to group
	r.groupUsers[params.GroupID] = append(r.groupUsers[params.GroupID], params.UserID)
	return nil
}

// DeleteUserGroup deletes a user-group association (soft delete)
func (r *InMemoryIamGroupRepository) DeleteUserGroup(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove group from user
	newUserGroups := make([]uuid.UUID, 0)
	for _, gid := range r.userGroups[userID] {
		if gid != groupID {
			newUserGroups = append(newUserGroups, gid)
		}
	}
	r.userGroups[userID] = newUserGroups

	// Remove user from group
	newGroupUsers := make([]uuid.UUID, 0)
	for _, uid := range r.groupUsers[groupID] {
		if uid != userID {
			newGroupUsers = append(newGroupUsers, uid)
		}
	}
	r.groupUsers[groupID] = newGroupUsers

	return nil
}

// SeedGroup adds a group directly (for testing/initialization)
func (r *InMemoryIamGroupRepository) SeedGroup(group Group) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groups[group.ID] = group
	if r.groupUsers[group.ID] == nil {
		r.groupUsers[group.ID] = []uuid.UUID{}
	}
}
