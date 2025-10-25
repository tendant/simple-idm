package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// fileIamData represents all IAM data stored in the file
type fileIamData struct {
	Users      map[uuid.UUID]User           `json:"users"`       // keyed by user ID
	Roles      map[uuid.UUID]Role           `json:"roles"`       // keyed by role ID
	UserRoles  map[uuid.UUID][]uuid.UUID    `json:"user_roles"`  // user ID -> role IDs
	Groups     map[uuid.UUID]Group          `json:"groups"`      // keyed by group ID
	UserGroups map[uuid.UUID][]uuid.UUID    `json:"user_groups"` // user ID -> group IDs
}

// FileIamRepository implements IamRepository using file-based storage
type FileIamRepository struct {
	dataDir string
	data    *fileIamData
	mutex   sync.RWMutex
}

// NewFileIamRepository creates a new file-based IAM repository
func NewFileIamRepository(dataDir string) (*FileIamRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileIamRepository{
		dataDir: dataDir,
		data: &fileIamData{
			Users:      make(map[uuid.UUID]User),
			Roles:      make(map[uuid.UUID]Role),
			UserRoles:  make(map[uuid.UUID][]uuid.UUID),
			Groups:     make(map[uuid.UUID]Group),
			UserGroups: make(map[uuid.UUID][]uuid.UUID),
		},
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// CreateUser creates a new user
func (r *FileIamRepository) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user := User{
		ID:             uuid.New(),
		Email:          params.Email,
		Name:           params.Name,
		LoginID:        params.LoginID,
		CreatedAt:      time.Now().UTC(),
		LastModifiedAt: time.Now().UTC(),
	}

	r.data.Users[user.ID] = user

	if err := r.save(); err != nil {
		// Rollback
		delete(r.data.Users, user.ID)
		return User{}, fmt.Errorf("failed to save: %w", err)
	}

	return user, nil
}

// GetUserWithRoles gets a user with their roles
func (r *FileIamRepository) GetUserWithRoles(ctx context.Context, id uuid.UUID) (UserWithRoles, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.data.Users[id]
	if !exists {
		return UserWithRoles{}, fmt.Errorf("user not found: %s", id)
	}

	// Get user roles
	var roles []Role
	if roleIDs, ok := r.data.UserRoles[id]; ok {
		for _, roleID := range roleIDs {
			if role, ok := r.data.Roles[roleID]; ok {
				roles = append(roles, role)
			}
		}
	}

	return UserWithRoles{
		User:  user,
		Roles: roles,
	}, nil
}

// FindUsersWithRoles retrieves all users with their roles
func (r *FileIamRepository) FindUsersWithRoles(ctx context.Context) ([]UserWithRoles, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var usersWithRoles []UserWithRoles
	for userID, user := range r.data.Users {
		// Skip deleted users
		if user.DeletedAt != nil {
			continue
		}

		// Get user roles
		var roles []Role
		if roleIDs, ok := r.data.UserRoles[userID]; ok {
			for _, roleID := range roleIDs {
				if role, ok := r.data.Roles[roleID]; ok {
					roles = append(roles, role)
				}
			}
		}

		usersWithRoles = append(usersWithRoles, UserWithRoles{
			User:  user,
			Roles: roles,
		})
	}

	return usersWithRoles, nil
}

// UpdateUser updates a user
func (r *FileIamRepository) UpdateUser(ctx context.Context, params UpdateUserParams) (User, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.data.Users[params.ID]
	if !exists {
		return User{}, fmt.Errorf("user not found: %s", params.ID)
	}

	// Update fields
	user.Email = params.Email
	user.Name = params.Name
	user.LoginID = params.LoginID
	user.LastModifiedAt = time.Now().UTC()

	r.data.Users[params.ID] = user

	if err := r.save(); err != nil {
		return User{}, fmt.Errorf("failed to save: %w", err)
	}

	return user, nil
}

// UpdateUserLoginID updates a user's login ID
func (r *FileIamRepository) UpdateUserLoginID(ctx context.Context, userID uuid.UUID, loginID *uuid.UUID) (User, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.data.Users[userID]
	if !exists {
		return User{}, fmt.Errorf("user not found: %s", userID)
	}

	// Update login ID
	user.LoginID = loginID
	user.LastModifiedAt = time.Now().UTC()

	r.data.Users[userID] = user

	if err := r.save(); err != nil {
		return User{}, fmt.Errorf("failed to save: %w", err)
	}

	return user, nil
}

// DeleteUser soft deletes a user
func (r *FileIamRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.data.Users[id]
	if !exists {
		return fmt.Errorf("user not found: %s", id)
	}

	// Soft delete
	now := time.Now().UTC()
	user.DeletedAt = &now
	user.LastModifiedAt = now

	r.data.Users[id] = user

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// DeleteUserRoles removes all roles from a user
func (r *FileIamRepository) DeleteUserRoles(ctx context.Context, userID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	delete(r.data.UserRoles, userID)

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// AnyUserExists checks if any users exist
func (r *FileIamRepository) AnyUserExists(ctx context.Context) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, user := range r.data.Users {
		// Skip deleted users
		if user.DeletedAt == nil {
			return true, nil
		}
	}

	return false, nil
}

// CreateUserRole assigns a role to a user
func (r *FileIamRepository) CreateUserRole(ctx context.Context, params UserRoleParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Verify user exists
	if _, exists := r.data.Users[params.UserID]; !exists {
		return fmt.Errorf("user not found: %s", params.UserID)
	}

	// Verify role exists
	if _, exists := r.data.Roles[params.RoleID]; !exists {
		return fmt.Errorf("role not found: %s", params.RoleID)
	}

	// Add role to user (check for duplicates)
	roles := r.data.UserRoles[params.UserID]
	for _, roleID := range roles {
		if roleID == params.RoleID {
			// Already assigned
			return nil
		}
	}

	roles = append(roles, params.RoleID)
	r.data.UserRoles[params.UserID] = roles

	if err := r.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// FindRoles retrieves all roles
func (r *FileIamRepository) FindRoles(ctx context.Context) ([]Role, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var roles []Role
	for _, role := range r.data.Roles {
		roles = append(roles, role)
	}

	return roles, nil
}

// CreateRole creates a new role
func (r *FileIamRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	role := Role{
		ID:   uuid.New(),
		Name: name,
	}

	r.data.Roles[role.ID] = role

	if err := r.save(); err != nil {
		// Rollback
		delete(r.data.Roles, role.ID)
		return uuid.Nil, fmt.Errorf("failed to save: %w", err)
	}

	return role.ID, nil
}

// FileIamGroupRepository implements IamGroupRepository using file-based storage
type FileIamGroupRepository struct {
	repo *FileIamRepository
}

// NewFileIamGroupRepository creates a new file-based IAM group repository
func NewFileIamGroupRepository(repo *FileIamRepository) *FileIamGroupRepository {
	return &FileIamGroupRepository{
		repo: repo,
	}
}

// CreateGroup creates a new group
func (r *FileIamGroupRepository) CreateGroup(ctx context.Context, params CreateGroupParams) (Group, error) {
	r.repo.mutex.Lock()
	defer r.repo.mutex.Unlock()

	group := Group{
		ID:          uuid.New(),
		Name:        params.Name,
		Description: params.Description,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	r.repo.data.Groups[group.ID] = group

	if err := r.repo.save(); err != nil {
		// Rollback
		delete(r.repo.data.Groups, group.ID)
		return Group{}, fmt.Errorf("failed to save: %w", err)
	}

	return group, nil
}

// GetGroup retrieves a group by ID
func (r *FileIamGroupRepository) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	r.repo.mutex.RLock()
	defer r.repo.mutex.RUnlock()

	group, exists := r.repo.data.Groups[id]
	if !exists {
		return Group{}, fmt.Errorf("group not found: %s", id)
	}

	return group, nil
}

// FindGroups retrieves all groups
func (r *FileIamGroupRepository) FindGroups(ctx context.Context) ([]Group, error) {
	r.repo.mutex.RLock()
	defer r.repo.mutex.RUnlock()

	var groups []Group
	for _, group := range r.repo.data.Groups {
		// Skip deleted groups
		if group.DeletedAt == nil {
			groups = append(groups, group)
		}
	}

	return groups, nil
}

// UpdateGroup updates a group
func (r *FileIamGroupRepository) UpdateGroup(ctx context.Context, params UpdateGroupParams) (Group, error) {
	r.repo.mutex.Lock()
	defer r.repo.mutex.Unlock()

	group, exists := r.repo.data.Groups[params.ID]
	if !exists {
		return Group{}, fmt.Errorf("group not found: %s", params.ID)
	}

	// Update fields
	group.Name = params.Name
	group.Description = params.Description
	group.UpdatedAt = time.Now().UTC()

	r.repo.data.Groups[params.ID] = group

	if err := r.repo.save(); err != nil {
		return Group{}, fmt.Errorf("failed to save: %w", err)
	}

	return group, nil
}

// DeleteGroup soft deletes a group
func (r *FileIamGroupRepository) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	r.repo.mutex.Lock()
	defer r.repo.mutex.Unlock()

	group, exists := r.repo.data.Groups[id]
	if !exists {
		return fmt.Errorf("group not found: %s", id)
	}

	// Soft delete
	now := time.Now().UTC()
	group.DeletedAt = &now
	group.UpdatedAt = now

	r.repo.data.Groups[id] = group

	if err := r.repo.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// FindGroupUsers retrieves all users in a group
func (r *FileIamGroupRepository) FindGroupUsers(ctx context.Context, groupID uuid.UUID) ([]User, error) {
	r.repo.mutex.RLock()
	defer r.repo.mutex.RUnlock()

	var users []User
	for userID, groupIDs := range r.repo.data.UserGroups {
		for _, gid := range groupIDs {
			if gid == groupID {
				if user, exists := r.repo.data.Users[userID]; exists {
					// Skip deleted users
					if user.DeletedAt == nil {
						users = append(users, user)
					}
				}
				break
			}
		}
	}

	return users, nil
}

// CreateUserGroup assigns a user to a group
func (r *FileIamGroupRepository) CreateUserGroup(ctx context.Context, params UserGroupParams) error {
	r.repo.mutex.Lock()
	defer r.repo.mutex.Unlock()

	// Verify user exists
	if _, exists := r.repo.data.Users[params.UserID]; !exists {
		return fmt.Errorf("user not found: %s", params.UserID)
	}

	// Verify group exists
	if _, exists := r.repo.data.Groups[params.GroupID]; !exists {
		return fmt.Errorf("group not found: %s", params.GroupID)
	}

	// Add group to user (check for duplicates)
	groups := r.repo.data.UserGroups[params.UserID]
	for _, groupID := range groups {
		if groupID == params.GroupID {
			// Already assigned
			return nil
		}
	}

	groups = append(groups, params.GroupID)
	r.repo.data.UserGroups[params.UserID] = groups

	if err := r.repo.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// UpsertUserGroup assigns a user to a group (creates if not exists)
func (r *FileIamGroupRepository) UpsertUserGroup(ctx context.Context, params UserGroupParams) error {
	// Same as CreateUserGroup for file-based implementation
	return r.CreateUserGroup(ctx, params)
}

// DeleteUserGroup removes a user from a group
func (r *FileIamGroupRepository) DeleteUserGroup(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) error {
	r.repo.mutex.Lock()
	defer r.repo.mutex.Unlock()

	groups := r.repo.data.UserGroups[userID]
	var newGroups []uuid.UUID
	for _, gid := range groups {
		if gid != groupID {
			newGroups = append(newGroups, gid)
		}
	}

	if len(newGroups) == 0 {
		delete(r.repo.data.UserGroups, userID)
	} else {
		r.repo.data.UserGroups[userID] = newGroups
	}

	if err := r.repo.save(); err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	return nil
}

// load reads IAM data from file
func (r *FileIamRepository) load() error {
	filePath := filepath.Join(r.dataDir, "iam.json")

	// If file doesn't exist, start with empty data
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty data
	if len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, r.data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// save writes IAM data to file atomically
func (r *FileIamRepository) save() error {
	data, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "iam.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "iam.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
