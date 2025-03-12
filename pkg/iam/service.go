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

	// Role operations
	CreateUserRole(ctx context.Context, params UserRoleParams) error
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
			ID interface{} `json:"id"`
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
				ID interface{} `json:"id"`
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

// CreateUserRole creates a user-role association
func (r *PostgresIamRepository) CreateUserRole(ctx context.Context, params UserRoleParams) error {
	// Convert domain model to iamdb model
	_, err := r.queries.CreateUserRole(ctx, iamdb.CreateUserRoleParams{
		UserID: params.UserID,
		RoleID: params.RoleID,
	})
	return err
}

// IamService provides IAM operations
type IamService struct {
	repo IamRepository
}

// NewIamService creates a new IAM service
func NewIamService(repo IamRepository) *IamService {
	return &IamService{
		repo: repo,
	}
}

// NewIamServiceWithQueries creates a new IAM service with iamdb.Queries
// This is a convenience function for backward compatibility
func NewIamServiceWithQueries(queries *iamdb.Queries) *IamService {
	repo := NewPostgresIamRepository(queries)
	return NewIamService(repo)
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
