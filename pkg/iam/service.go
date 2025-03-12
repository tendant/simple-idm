package iam

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

// IamRepository defines the interface for IAM operations
type IamRepository interface {
	// User operations
	CreateUser(ctx context.Context, arg iamdb.CreateUserParams) (iamdb.User, error)
	GetUserWithRoles(ctx context.Context, id uuid.UUID) (iamdb.GetUserWithRolesRow, error)
	FindUsersWithRoles(ctx context.Context) ([]iamdb.FindUsersWithRolesRow, error)
	UpdateUser(ctx context.Context, arg iamdb.UpdateUserParams) (iamdb.User, error)
	UpdateUserLoginID(ctx context.Context, arg iamdb.UpdateUserLoginIDParams) (iamdb.User, error)
	DeleteUser(ctx context.Context, id uuid.UUID) error
	DeleteUserRoles(ctx context.Context, userID uuid.UUID) error

	// Role operations
	CreateUserRole(ctx context.Context, arg iamdb.CreateUserRoleParams) (iamdb.UserRole, error)
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
func (r *PostgresIamRepository) CreateUser(ctx context.Context, arg iamdb.CreateUserParams) (iamdb.User, error) {
	return r.queries.CreateUser(ctx, arg)
}

// GetUserWithRoles gets a user with their roles
func (r *PostgresIamRepository) GetUserWithRoles(ctx context.Context, id uuid.UUID) (iamdb.GetUserWithRolesRow, error) {
	return r.queries.GetUserWithRoles(ctx, id)
}

// FindUsersWithRoles finds all users with their roles
func (r *PostgresIamRepository) FindUsersWithRoles(ctx context.Context) ([]iamdb.FindUsersWithRolesRow, error) {
	return r.queries.FindUsersWithRoles(ctx)
}

// UpdateUser updates a user
func (r *PostgresIamRepository) UpdateUser(ctx context.Context, arg iamdb.UpdateUserParams) (iamdb.User, error) {
	return r.queries.UpdateUser(ctx, arg)
}

// UpdateUserLoginID updates a user's login ID
func (r *PostgresIamRepository) UpdateUserLoginID(ctx context.Context, arg iamdb.UpdateUserLoginIDParams) (iamdb.User, error) {
	return r.queries.UpdateUserLoginID(ctx, arg)
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
func (r *PostgresIamRepository) CreateUserRole(ctx context.Context, arg iamdb.CreateUserRoleParams) (iamdb.UserRole, error) {
	return r.queries.CreateUserRole(ctx, arg)
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

func (s *IamService) CreateUser(ctx context.Context, email, username, name string, roleIds []uuid.UUID, loginID string) (iamdb.GetUserWithRolesRow, error) {
	// Validate email
	if email == "" {
		return iamdb.GetUserWithRolesRow{}, fmt.Errorf("email is required")
	}
	// Validate username
	if username == "" {
		return iamdb.GetUserWithRolesRow{}, fmt.Errorf("username is required")
	}

	// Create the user first
	nullString := sql.NullString{String: name, Valid: name != ""}
	nullLoginID := sql.NullString{String: loginID, Valid: loginID != ""}

	// Note: Username field is removed as it doesn't exist in the struct
	user, err := s.repo.CreateUser(ctx, iamdb.CreateUserParams{
		Email:   email,
		Name:    nullString,
		LoginID: utils.NullStringToNullUUID(nullLoginID),
	})
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to create user: %w", err)
	}

	// If there are roles to assign, create the user-role associations
	if len(roleIds) > 0 {
		slog.Info("Assigning roles to user", "userId", user.ID, "roleIds", roleIds)
		// Insert role assignments one by one
		for _, roleId := range roleIds {
			slog.Info("Assigning role", "userId", user.ID, "roleId", roleId)
			_, err = s.repo.CreateUserRole(ctx, iamdb.CreateUserRoleParams{
				UserID: user.ID,
				RoleID: roleId,
			})
			if err != nil {
				slog.Error("Failed to assign role", "error", err, "userId", user.ID, "roleId", roleId)
				return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to assign role: %w", err)
			}
		}
	} else {
		slog.Info("No roles to assign", "userId", user.ID)
	}

	// Get the user with roles
	userWithRoles, err := s.repo.GetUserWithRoles(ctx, user.ID)
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to get user with roles: %w", err)
	}

	return userWithRoles, nil
}

func (s *IamService) FindUsers(ctx context.Context) ([]iamdb.FindUsersWithRolesRow, error) {
	return s.repo.FindUsersWithRoles(ctx)
}

func (s *IamService) GetUser(ctx context.Context, userId uuid.UUID) (iamdb.GetUserWithRolesRow, error) {
	return s.repo.GetUserWithRoles(ctx, userId)
}

func (s *IamService) UpdateUser(ctx context.Context, userId uuid.UUID, name string, roleIds []uuid.UUID, loginId *uuid.UUID) (iamdb.GetUserWithRolesRow, error) {
	// Update the user's name and login ID if provided
	nullString := sql.NullString{String: name, Valid: name != ""}

	// Create update params
	updateParams := iamdb.UpdateUserParams{
		ID:   userId,
		Name: nullString,
	}

	// Update the user
	_, err := s.repo.UpdateUser(ctx, updateParams)
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, err
	}

	// If loginId is provided, update the user's login ID
	if loginId != nil {
		// Create a NullUUID for the login ID
		nullUUID := uuid.NullUUID{UUID: *loginId, Valid: true}

		// Update the user's login ID
		_, err := s.repo.UpdateUserLoginID(ctx, iamdb.UpdateUserLoginIDParams{
			ID:      userId,
			LoginID: nullUUID,
		})
		if err != nil {
			return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to update user login ID: %w", err)
		}
	}

	// Delete existing roles
	err = s.repo.DeleteUserRoles(ctx, userId)
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, err
	}

	// If there are new roles to assign, create the user-role associations
	if len(roleIds) > 0 {
		// Insert role assignments one by one
		for _, roleId := range roleIds {
			_, err = s.repo.CreateUserRole(ctx, iamdb.CreateUserRoleParams{
				UserID: userId,
				RoleID: roleId,
			})
			if err != nil {
				return iamdb.GetUserWithRolesRow{}, err
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
