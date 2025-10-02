package iam

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"golang.org/x/exp/slog"
)

// IamRepository defines the interface for IAM operations
type IamRepository interface {
	// User operations
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	GetUserWithRoles(ctx context.Context, id uuid.UUID) (UserWithRoles, error)
	FindUsersWithRoles(ctx context.Context) ([]UserWithRoles, error)
	UpdateUser(ctx context.Context, params UpdateUserParams) (User, error)
	UpdateUserLoginID(ctx context.Context, userID uuid.UUID, loginID *uuid.UUID) (User, error)
	DeleteUser(ctx context.Context, id uuid.UUID) error
	DeleteUserRoles(ctx context.Context, userID uuid.UUID) error
	AnyUserExists(ctx context.Context) (bool, error)

	// Role operations
	CreateUserRole(ctx context.Context, params UserRoleParams) error
	FindRoles(ctx context.Context) ([]Role, error)
	CreateRole(ctx context.Context, name string) (uuid.UUID, error)
}

// IamGroupRepository defines the interface for group operations
type IamGroupRepository interface {
	// Group operations
	CreateGroup(ctx context.Context, params CreateGroupParams) (Group, error)
	GetGroup(ctx context.Context, id uuid.UUID) (Group, error)
	FindGroups(ctx context.Context) ([]Group, error)
	UpdateGroup(ctx context.Context, params UpdateGroupParams) (Group, error)
	DeleteGroup(ctx context.Context, id uuid.UUID) error
	FindGroupUsers(ctx context.Context, groupID uuid.UUID) ([]User, error)
	CreateUserGroup(ctx context.Context, params UserGroupParams) error
	UpsertUserGroup(ctx context.Context, params UserGroupParams) error
	DeleteUserGroup(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) error
}

// PostgresIamRepository implements IamRepository using iamdb.Queries
type PostgresIamRepository struct {
	queries *iamdb.Queries
}

// NewPostgresIamRepository creates a new PostgreSQL-based IAM repository
func NewPostgresIamRepository(queries *iamdb.Queries) *PostgresIamRepository {
	return &PostgresIamRepository{
		queries: queries,
	}
}

// CreateUser creates a new user
func (r *PostgresIamRepository) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	// Convert domain model to iamdb model
	var nullName sql.NullString
	if params.Name != "" {
		nullName = sql.NullString{String: params.Name, Valid: true}
	}

	var nullLoginID uuid.NullUUID
	if params.LoginID != nil {
		nullLoginID = uuid.NullUUID{UUID: *params.LoginID, Valid: true}
	}

	// Call the database
	dbUser, err := r.queries.CreateUser(ctx, iamdb.CreateUserParams{
		Email:   params.Email,
		Name:    nullName,
		LoginID: nullLoginID,
	})
	if err != nil {
		return User{}, err
	}

	// Convert back to domain model
	var loginID *uuid.UUID
	if dbUser.LoginID.Valid {
		id := dbUser.LoginID.UUID
		loginID = &id
	}

	var deletedAt *time.Time
	if dbUser.DeletedAt.Valid {
		dt := dbUser.DeletedAt.Time
		deletedAt = &dt
	}

	var createdBy string
	if dbUser.CreatedBy.Valid {
		createdBy = dbUser.CreatedBy.String
	}

	var name string
	if dbUser.Name.Valid {
		name = dbUser.Name.String
	}

	return User{
		ID:             dbUser.ID,
		CreatedAt:      dbUser.CreatedAt,
		LastModifiedAt: dbUser.LastModifiedAt,
		DeletedAt:      deletedAt,
		CreatedBy:      createdBy,
		Email:          dbUser.Email,
		Name:           name,
		LoginID:        loginID,
	}, nil
}

// GetUserWithRoles gets a user with their roles
func (r *PostgresIamRepository) GetUserWithRoles(ctx context.Context, id uuid.UUID) (UserWithRoles, error) {
	// Call the database
	dbUser, err := r.queries.GetUserWithRoles(ctx, id)
	if err != nil {
		return UserWithRoles{}, err
	}

	// Convert to domain model
	var loginID *uuid.UUID
	if dbUser.LoginID.Valid {
		id := dbUser.LoginID.UUID
		loginID = &id
	}

	var deletedAt *time.Time
	if dbUser.DeletedAt.Valid {
		dt := dbUser.DeletedAt.Time
		deletedAt = &dt
	}

	var createdBy string
	if dbUser.CreatedBy.Valid {
		createdBy = dbUser.CreatedBy.String
	}

	var name string
	if dbUser.Name.Valid {
		name = dbUser.Name.String
	}

	var username string
	if dbUser.Username.Valid {
		username = dbUser.Username.String
	}

	// Parse roles from JSON
	roles := []Role{}
	if len(dbUser.Roles) > 0 {
		var dbRoles []struct {
			ID   interface{} `json:"id"`
			Name interface{} `json:"name"`
		}
		if err := json.Unmarshal(dbUser.Roles, &dbRoles); err != nil {
			return UserWithRoles{}, fmt.Errorf("failed to unmarshal roles: %w", err)
		}

		for _, r := range dbRoles {
			// Skip null roles
			if r.ID == nil || r.Name == nil {
				continue
			}

			idStr, ok := r.ID.(string)
			if !ok {
				continue
			}

			roleID, err := uuid.Parse(idStr)
			if err != nil {
				continue
			}

			name, ok := r.Name.(string)
			if !ok {
				continue
			}

			roles = append(roles, Role{
				ID:   roleID,
				Name: name,
			})
		}
	}

	return UserWithRoles{
		User: User{
			ID:             dbUser.ID,
			CreatedAt:      dbUser.CreatedAt,
			LastModifiedAt: dbUser.LastModifiedAt,
			DeletedAt:      deletedAt,
			CreatedBy:      createdBy,
			Email:          dbUser.Email,
			Name:           name,
			LoginID:        loginID,
			Username:       username,
		},
		Roles: roles,
	}, nil
}

// FindUsersWithRoles finds all users with their roles
func (r *PostgresIamRepository) FindUsersWithRoles(ctx context.Context) ([]UserWithRoles, error) {
	// Call the database
	dbUsers, err := r.queries.FindUsersWithRoles(ctx)
	if err != nil {
		return nil, err
	}

	// Convert to domain models
	users := make([]UserWithRoles, 0, len(dbUsers))
	for _, dbUser := range dbUsers {
		// Convert to domain model
		var loginID *uuid.UUID
		if dbUser.LoginID.Valid {
			id := dbUser.LoginID.UUID
			loginID = &id
		}

		var deletedAt *time.Time
		if dbUser.DeletedAt.Valid {
			dt := dbUser.DeletedAt.Time
			deletedAt = &dt
		}

		var createdBy string
		if dbUser.CreatedBy.Valid {
			createdBy = dbUser.CreatedBy.String
		}

		var name string
		if dbUser.Name.Valid {
			name = dbUser.Name.String
		}

		var username string
		if dbUser.Username.Valid {
			username = dbUser.Username.String
		}

		// Parse roles from JSON
		roles := []Role{}
		if len(dbUser.Roles) > 0 {
			var dbRoles []struct {
				ID   interface{} `json:"id"`
				Name interface{} `json:"name"`
			}
			if err := json.Unmarshal(dbUser.Roles, &dbRoles); err != nil {
				return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
			}

			for _, r := range dbRoles {
				// Skip null roles
				if r.ID == nil || r.Name == nil {
					continue
				}

				idStr, ok := r.ID.(string)
				if !ok {
					continue
				}

				roleID, err := uuid.Parse(idStr)
				if err != nil {
					continue
				}

				name, ok := r.Name.(string)
				if !ok {
					continue
				}

				roles = append(roles, Role{
					ID:   roleID,
					Name: name,
				})
			}
		}

		users = append(users, UserWithRoles{
			User: User{
				ID:             dbUser.ID,
				CreatedAt:      dbUser.CreatedAt,
				LastModifiedAt: dbUser.LastModifiedAt,
				DeletedAt:      deletedAt,
				CreatedBy:      createdBy,
				Email:          dbUser.Email,
				Name:           name,
				LoginID:        loginID,
				Username:       username,
			},
			Roles: roles,
		})
	}

	return users, nil
}

// UpdateUser updates a user
func (r *PostgresIamRepository) UpdateUser(ctx context.Context, params UpdateUserParams) (User, error) {
	// Convert domain model to iamdb model
	var nullName sql.NullString
	if params.Name != "" {
		nullName = sql.NullString{String: params.Name, Valid: true}
	}

	// Call the database
	dbUser, err := r.queries.UpdateUser(ctx, iamdb.UpdateUserParams{
		ID:   params.ID,
		Name: nullName,
	})
	if err != nil {
		return User{}, err
	}

	// Convert back to domain model
	var loginID *uuid.UUID
	if dbUser.LoginID.Valid {
		id := dbUser.LoginID.UUID
		loginID = &id
	}

	var deletedAt *time.Time
	if dbUser.DeletedAt.Valid {
		dt := dbUser.DeletedAt.Time
		deletedAt = &dt
	}

	var createdBy string
	if dbUser.CreatedBy.Valid {
		createdBy = dbUser.CreatedBy.String
	}

	var name string
	if dbUser.Name.Valid {
		name = dbUser.Name.String
	}

	return User{
		ID:             dbUser.ID,
		CreatedAt:      dbUser.CreatedAt,
		LastModifiedAt: dbUser.LastModifiedAt,
		DeletedAt:      deletedAt,
		CreatedBy:      createdBy,
		Email:          dbUser.Email,
		Name:           name,
		LoginID:        loginID,
	}, nil
}

// UpdateUserLoginID updates a user's login ID
func (r *PostgresIamRepository) UpdateUserLoginID(ctx context.Context, userID uuid.UUID, loginID *uuid.UUID) (User, error) {
	// Convert to iamdb model
	var nullLoginID uuid.NullUUID
	if loginID != nil {
		nullLoginID = uuid.NullUUID{UUID: *loginID, Valid: true}
	}

	// Call the database
	dbUser, err := r.queries.UpdateUserLoginID(ctx, iamdb.UpdateUserLoginIDParams{
		ID:      userID,
		LoginID: nullLoginID,
	})
	if err != nil {
		return User{}, err
	}

	// Convert back to domain model
	var resultLoginID *uuid.UUID
	if dbUser.LoginID.Valid {
		id := dbUser.LoginID.UUID
		resultLoginID = &id
	}

	var deletedAt *time.Time
	if dbUser.DeletedAt.Valid {
		dt := dbUser.DeletedAt.Time
		deletedAt = &dt
	}

	var createdBy string
	if dbUser.CreatedBy.Valid {
		createdBy = dbUser.CreatedBy.String
	}

	var name string
	if dbUser.Name.Valid {
		name = dbUser.Name.String
	}

	return User{
		ID:             dbUser.ID,
		CreatedAt:      dbUser.CreatedAt,
		LastModifiedAt: dbUser.LastModifiedAt,
		DeletedAt:      deletedAt,
		CreatedBy:      createdBy,
		Email:          dbUser.Email,
		Name:           name,
		LoginID:        resultLoginID,
	}, nil
}

// DeleteUser deletes a user
func (r *PostgresIamRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteUser(ctx, id)
}

// DeleteUserRoles deletes all roles for a user
func (r *PostgresIamRepository) DeleteUserRoles(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DeleteUserRoles(ctx, userID)
}

// AnyUserExists checks if any user exists in the system
func (r *PostgresIamRepository) AnyUserExists(ctx context.Context) (bool, error) {
	return r.queries.AnyUserExists(ctx)
}

// CreateUserRole creates a user-role association
func (r *PostgresIamRepository) CreateUserRole(ctx context.Context, params UserRoleParams) error {
	// Convert domain model to iamdb model
	_, err := r.queries.CreateUserRole(ctx, iamdb.CreateUserRoleParams{
		UserID: params.UserID,
		RoleID: params.RoleID,
	})
	return err
}

func (r *PostgresIamRepository) FindRoles(ctx context.Context) ([]Role, error) {
	// Call the database
	dbRoles, err := r.queries.FindRoles(ctx)
	if err != nil {
		return nil, err
	}

	// Convert to domain models
	roles := make([]Role, 0, len(dbRoles))
	for _, dbRole := range dbRoles {
		roles = append(roles, Role{
			ID:   dbRole.ID,
			Name: dbRole.Name,
		})
	}

	return roles, nil
}

func (r *PostgresIamRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	// Call the database
	dbRole, err := r.queries.CreateRole(ctx, name)
	if err != nil {
		return uuid.Nil, err
	}

	return dbRole, nil
}

// PostgresIamGroupRepository implements IamGroupRepository using iamdb.Queries
type PostgresIamGroupRepository struct {
	queries *iamdb.Queries
}

// NewPostgresIamGroupRepository creates a new PostgreSQL-based IAM group repository
func NewPostgresIamGroupRepository(queries *iamdb.Queries) *PostgresIamGroupRepository {
	return &PostgresIamGroupRepository{
		queries: queries,
	}
}

// CreateGroup creates a new group
func (r *PostgresIamGroupRepository) CreateGroup(ctx context.Context, params CreateGroupParams) (Group, error) {
	// Convert domain model to iamdb model
	var nullDescription sql.NullString
	if params.Description != "" {
		nullDescription = sql.NullString{String: params.Description, Valid: true}
	}

	// Call the database
	dbGroup, err := r.queries.CreateGroup(ctx, iamdb.CreateGroupParams{
		Name:        params.Name,
		Description: nullDescription,
	})
	if err != nil {
		return Group{}, err
	}

	// Convert back to domain model
	var deletedAt *time.Time
	if dbGroup.DeletedAt.Valid {
		dt := dbGroup.DeletedAt.Time
		deletedAt = &dt
	}

	var description string
	if dbGroup.Description.Valid {
		description = dbGroup.Description.String
	}

	return Group{
		ID:          dbGroup.ID,
		CreatedAt:   dbGroup.CreatedAt.Time,
		UpdatedAt:   dbGroup.UpdatedAt.Time,
		DeletedAt:   deletedAt,
		Name:        dbGroup.Name,
		Description: description,
	}, nil
}

// GetGroup gets a group by ID
func (r *PostgresIamGroupRepository) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	// Call the database
	dbGroup, err := r.queries.GetGroupById(ctx, id)
	if err != nil {
		return Group{}, err
	}

	// Convert to domain model
	var deletedAt *time.Time
	if dbGroup.DeletedAt.Valid {
		dt := dbGroup.DeletedAt.Time
		deletedAt = &dt
	}

	var description string
	if dbGroup.Description.Valid {
		description = dbGroup.Description.String
	}

	return Group{
		ID:          dbGroup.ID,
		CreatedAt:   dbGroup.CreatedAt.Time,
		UpdatedAt:   dbGroup.UpdatedAt.Time,
		DeletedAt:   deletedAt,
		Name:        dbGroup.Name,
		Description: description,
	}, nil
}

// FindGroups finds all groups
func (r *PostgresIamGroupRepository) FindGroups(ctx context.Context) ([]Group, error) {
	// Call the database
	dbGroups, err := r.queries.FindGroups(ctx)
	if err != nil {
		return nil, err
	}

	// Convert to domain models
	groups := make([]Group, 0, len(dbGroups))
	for _, dbGroup := range dbGroups {
		var description string
		if dbGroup.Description.Valid {
			description = dbGroup.Description.String
		}

		groups = append(groups, Group{
			ID:          dbGroup.ID,
			CreatedAt:   dbGroup.CreatedAt.Time,
			UpdatedAt:   dbGroup.UpdatedAt.Time,
			DeletedAt:   nil, // FindGroups only returns non-deleted groups
			Name:        dbGroup.Name,
			Description: description,
		})
	}

	return groups, nil
}

// UpdateGroup updates a group
func (r *PostgresIamGroupRepository) UpdateGroup(ctx context.Context, params UpdateGroupParams) (Group, error) {
	// Convert domain model to iamdb model
	var nullDescription sql.NullString
	if params.Description != "" {
		nullDescription = sql.NullString{String: params.Description, Valid: true}
	}

	// Call the database
	dbGroup, err := r.queries.UpdateGroup(ctx, iamdb.UpdateGroupParams{
		ID:          params.ID,
		Name:        params.Name,
		Description: nullDescription,
	})
	if err != nil {
		return Group{}, err
	}

	// Convert back to domain model
	var deletedAt *time.Time
	if dbGroup.DeletedAt.Valid {
		dt := dbGroup.DeletedAt.Time
		deletedAt = &dt
	}

	var description string
	if dbGroup.Description.Valid {
		description = dbGroup.Description.String
	}

	return Group{
		ID:          dbGroup.ID,
		CreatedAt:   dbGroup.CreatedAt.Time,
		UpdatedAt:   dbGroup.UpdatedAt.Time,
		DeletedAt:   deletedAt,
		Name:        dbGroup.Name,
		Description: description,
	}, nil
}

// DeleteGroup deletes a group (soft delete)
func (r *PostgresIamGroupRepository) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteGroup(ctx, id)
}

// FindGroupUsers finds all users in a group
func (r *PostgresIamGroupRepository) FindGroupUsers(ctx context.Context, groupID uuid.UUID) ([]User, error) {
	// Call the database
	dbUsers, err := r.queries.FindGroupUsers(ctx, groupID)
	if err != nil {
		return nil, err
	}

	// Convert to domain models
	users := make([]User, 0, len(dbUsers))
	for _, dbUser := range dbUsers {
		var name string
		if dbUser.Name.Valid {
			name = dbUser.Name.String
		}

		users = append(users, User{
			ID:    dbUser.ID,
			Email: dbUser.Email,
			Name:  name,
		})
	}

	return users, nil
}

// CreateUserGroup creates a user-group association
func (r *PostgresIamGroupRepository) CreateUserGroup(ctx context.Context, params UserGroupParams) error {
	// Convert domain model to iamdb model
	_, err := r.queries.CreateUserGroup(ctx, iamdb.CreateUserGroupParams{
		UserID:  params.UserID,
		GroupID: params.GroupID,
	})
	return err
}

// UpsertUserGroup creates or reactivates a user-group association
func (r *PostgresIamGroupRepository) UpsertUserGroup(ctx context.Context, params UserGroupParams) error {
	// Convert domain model to iamdb model
	_, err := r.queries.UpsertUserGroup(ctx, iamdb.UpsertUserGroupParams{
		UserID:  params.UserID,
		GroupID: params.GroupID,
	})
	return err
}

// DeleteUserGroup deletes a user-group association (soft delete)
func (r *PostgresIamGroupRepository) DeleteUserGroup(ctx context.Context, userID uuid.UUID, groupID uuid.UUID) error {
	return r.queries.DeleteUserGroup(ctx, iamdb.DeleteUserGroupParams{
		UserID:  userID,
		GroupID: groupID,
	})
}

// IamService provides IAM operations
type IamService struct {
	repo      IamRepository
	groupRepo IamGroupRepository
}

// IamServiceOption is a function that configures an IamService
type IamServiceOption func(*IamService)

// WithGroupRepository sets the group repository for the IamService
func WithGroupRepository(groupRepo IamGroupRepository) IamServiceOption {
	return func(s *IamService) {
		s.groupRepo = groupRepo
	}
}

// NewIamService creates a new IAM service
func NewIamService(repo IamRepository) *IamService {
	return &IamService{
		repo: repo,
	}
}

// NewIamServiceWithOptions creates a new IAM service with the given options
func NewIamServiceWithOptions(repo IamRepository, opts ...IamServiceOption) *IamService {
	s := &IamService{
		repo: repo,
	}

	// Apply all options
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// NewIamServiceWithQueries creates a new IAM service with iamdb.Queries
// This is a convenience function for backward compatibility
func NewIamServiceWithQueries(queries *iamdb.Queries) *IamService {
	repo := NewPostgresIamRepository(queries)
	return NewIamService(repo)
}

// NewIamServiceWithQueriesAndGroups creates a new IAM service with iamdb.Queries and group support
// This is a convenience function for easy setup with groups
func NewIamServiceWithQueriesAndGroups(queries *iamdb.Queries) *IamService {
	repo := NewPostgresIamRepository(queries)
	groupRepo := NewPostgresIamGroupRepository(queries)
	return NewIamServiceWithOptions(repo, WithGroupRepository(groupRepo))
}

func (s *IamService) CreateUser(ctx context.Context, email, username, name string, roleIds []uuid.UUID, loginID string) (UserWithRoles, error) {
	// Validate email
	if email == "" {
		return UserWithRoles{}, fmt.Errorf("email is required")
	}
	// Validate username
	if username == "" {
		return UserWithRoles{}, fmt.Errorf("username is required")
	}

	// Create the user first
	var loginUUID *uuid.UUID
	if loginID != "" {
		parsedID, err := uuid.Parse(loginID)
		if err != nil {
			return UserWithRoles{}, fmt.Errorf("invalid login ID: %w", err)
		}
		loginUUID = &parsedID
	}

	// Create user with domain model
	params := CreateUserParams{
		Email:   email,
		Name:    name,
		LoginID: loginUUID,
	}

	user, err := s.repo.CreateUser(ctx, params)
	if err != nil {
		return UserWithRoles{}, fmt.Errorf("failed to create user: %w", err)
	}

	// If there are roles to assign, create the user-role associations
	if len(roleIds) > 0 {
		slog.Info("Assigning roles to user", "userId", user.ID, "roleIds", roleIds)
		// Insert role assignments one by one
		for _, roleId := range roleIds {
			slog.Info("Assigning role", "userId", user.ID, "roleId", roleId)
			err = s.repo.CreateUserRole(ctx, UserRoleParams{
				UserID: user.ID,
				RoleID: roleId,
			})
			if err != nil {
				slog.Error("Failed to assign role", "error", err, "userId", user.ID, "roleId", roleId)
				return UserWithRoles{}, fmt.Errorf("failed to assign role: %w", err)
			}
		}
	} else {
		slog.Info("No roles to assign", "userId", user.ID)
	}

	// Get the user with roles
	userWithRoles, err := s.repo.GetUserWithRoles(ctx, user.ID)
	if err != nil {
		return UserWithRoles{}, fmt.Errorf("failed to get user with roles: %w", err)
	}

	return userWithRoles, nil
}

func (s *IamService) FindUsers(ctx context.Context) ([]UserWithRoles, error) {
	return s.repo.FindUsersWithRoles(ctx)
}

func (s *IamService) GetUser(ctx context.Context, userId uuid.UUID) (UserWithRoles, error) {
	return s.repo.GetUserWithRoles(ctx, userId)
}

func (s *IamService) UpdateUser(ctx context.Context, userId uuid.UUID, name string, roleIds []uuid.UUID, loginId *uuid.UUID) (UserWithRoles, error) {
	// Update the user's name and login ID if provided
	// Create update params with domain model
	updateParams := UpdateUserParams{
		ID:   userId,
		Name: name,
	}

	// Update the user
	_, err := s.repo.UpdateUser(ctx, updateParams)
	if err != nil {
		return UserWithRoles{}, err
	}

	// If loginId is provided, update the user's login ID
	if loginId != nil {
		// Update the user's login ID using domain model
		_, err := s.repo.UpdateUserLoginID(ctx, userId, loginId)
		if err != nil {
			return UserWithRoles{}, fmt.Errorf("failed to update user login ID: %w", err)
		}
	}

	// Delete existing roles
	err = s.repo.DeleteUserRoles(ctx, userId)
	if err != nil {
		return UserWithRoles{}, err
	}

	// If there are new roles to assign, create the user-role associations
	if len(roleIds) > 0 {
		// Insert role assignments one by one
		for _, roleId := range roleIds {
			err = s.repo.CreateUserRole(ctx, UserRoleParams{
				UserID: userId,
				RoleID: roleId,
			})
			if err != nil {
				return UserWithRoles{}, err
			}
		}
	}

	// Return the updated user with roles
	return s.repo.GetUserWithRoles(ctx, userId)
}

func (s *IamService) DeleteUser(ctx context.Context, userId uuid.UUID) error {
	// Check if user exists
	_, err := s.repo.GetUserWithRoles(ctx, userId)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return s.repo.DeleteUser(ctx, userId)
}

func (s *IamService) FindRoles(ctx context.Context) ([]Role, error) {
	{
		roles, err := s.repo.FindRoles(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to find roles: %w", err)
		}
		return roles, nil
	}
}

func (s *IamService) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	if name == "" {
		return uuid.Nil, fmt.Errorf("role name is required")
	}

	roleID, err := s.repo.CreateRole(ctx, name)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create role: %w", err)
	}

	return roleID, nil
}

func (s *IamService) AnyUserExists(ctx context.Context) (bool, error) {
	return s.repo.AnyUserExists(ctx)
}

// Group management methods (only available if group repository is configured)

// CreateGroup creates a new group
func (s *IamService) CreateGroup(ctx context.Context, name, description string) (Group, error) {
	if s.groupRepo == nil {
		return Group{}, fmt.Errorf("group operations not supported: group repository not configured")
	}

	// Validate name
	if name == "" {
		return Group{}, fmt.Errorf("group name is required")
	}

	// Create group with domain model
	params := CreateGroupParams{
		Name:        name,
		Description: description,
	}

	group, err := s.groupRepo.CreateGroup(ctx, params)
	if err != nil {
		return Group{}, fmt.Errorf("failed to create group: %w", err)
	}

	return group, nil
}

// FindGroups finds all groups
func (s *IamService) FindGroups(ctx context.Context) ([]Group, error) {
	if s.groupRepo == nil {
		return nil, fmt.Errorf("group operations not supported: group repository not configured")
	}

	return s.groupRepo.FindGroups(ctx)
}

// GetGroup gets a group by ID
func (s *IamService) GetGroup(ctx context.Context, groupID uuid.UUID) (Group, error) {
	if s.groupRepo == nil {
		return Group{}, fmt.Errorf("group operations not supported: group repository not configured")
	}

	return s.groupRepo.GetGroup(ctx, groupID)
}

// UpdateGroup updates a group
func (s *IamService) UpdateGroup(ctx context.Context, groupID uuid.UUID, name, description string) (Group, error) {
	if s.groupRepo == nil {
		return Group{}, fmt.Errorf("group operations not supported: group repository not configured")
	}

	// Validate name
	if name == "" {
		return Group{}, fmt.Errorf("group name is required")
	}

	// Update group with domain model
	params := UpdateGroupParams{
		ID:          groupID,
		Name:        name,
		Description: description,
	}

	group, err := s.groupRepo.UpdateGroup(ctx, params)
	if err != nil {
		return Group{}, fmt.Errorf("failed to update group: %w", err)
	}

	return group, nil
}

// DeleteGroup deletes a group
func (s *IamService) DeleteGroup(ctx context.Context, groupID uuid.UUID) error {
	if s.groupRepo == nil {
		return fmt.Errorf("group operations not supported: group repository not configured")
	}

	// Check if group exists
	_, err := s.groupRepo.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	return s.groupRepo.DeleteGroup(ctx, groupID)
}

// FindGroupUsers finds all users in a group
func (s *IamService) FindGroupUsers(ctx context.Context, groupID uuid.UUID) ([]User, error) {
	if s.groupRepo == nil {
		return nil, fmt.Errorf("group operations not supported: group repository not configured")
	}

	return s.groupRepo.FindGroupUsers(ctx, groupID)
}

// AddUserToGroup adds a user to a group
func (s *IamService) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	if s.groupRepo == nil {
		return fmt.Errorf("group operations not supported: group repository not configured")
	}

	// Create or reactivate user-group association using upsert
	params := UserGroupParams{
		UserID:  userID,
		GroupID: groupID,
	}

	err := s.groupRepo.UpsertUserGroup(ctx, params)
	if err != nil {
		slog.Error("Failed to add user to group", "error", err, "userId", userID, "groupId", groupID)
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	return nil
}

// RemoveUserFromGroup removes a user from a group
func (s *IamService) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	if s.groupRepo == nil {
		return fmt.Errorf("group operations not supported: group repository not configured")
	}

	err := s.groupRepo.DeleteUserGroup(ctx, userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	return nil
}

// HasGroupSupport returns true if the service has group support enabled
func (s *IamService) HasGroupSupport() bool {
	return s.groupRepo != nil
}
