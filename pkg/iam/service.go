package iam

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
)

type IamService struct {
	queries *iamdb.Queries
}

func NewIamService(queries *iamdb.Queries) *IamService {
	return &IamService{
		queries: queries,
	}
}

func (s *IamService) CreateUser(ctx context.Context, email, username, name string, roleIds []uuid.UUID) (iamdb.GetUserWithRolesRow, error) {
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
	user, err := s.queries.CreateUser(ctx, iamdb.CreateUserParams{
		Email:    email,
		Username: sql.NullString{String: username, Valid: true},
		Name:     nullString,
	})
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to create user: %w", err)
	}

	// If there are roles to assign, create the user-role associations
	if len(roleIds) > 0 {
		// Insert role assignments one by one
		for _, roleId := range roleIds {
			_, err = s.queries.CreateUserRole(ctx, iamdb.CreateUserRoleParams{
				UserID: user.ID,
				RoleID: roleId,
			})
			if err != nil {
				return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to assign role: %w", err)
			}
		}
	}

	// Get the user with roles
	userWithRoles, err := s.queries.GetUserWithRoles(ctx, user.ID)
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, fmt.Errorf("failed to get user with roles: %w", err)
	}

	return userWithRoles, nil
}

func (s *IamService) FindUsers(ctx context.Context) ([]iamdb.FindUsersWithRolesRow, error) {
	return s.queries.FindUsersWithRoles(ctx)
}

func (s *IamService) GetUser(ctx context.Context, userId uuid.UUID) (iamdb.GetUserWithRolesRow, error) {
	return s.queries.GetUserWithRoles(ctx, userId)
}

func (s *IamService) UpdateUser(ctx context.Context, userId uuid.UUID, name string, roleIds []uuid.UUID) (iamdb.GetUserWithRolesRow, error) {
	// Update the user's name
	nullString := sql.NullString{String: name, Valid: name != ""}
	_, err := s.queries.UpdateUser(ctx, iamdb.UpdateUserParams{
		ID: userId,
		Name: nullString,
	})
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, err
	}

	// Delete existing roles
	err = s.queries.DeleteUserRoles(ctx, userId)
	if err != nil {
		return iamdb.GetUserWithRolesRow{}, err
	}

	// If there are new roles to assign, create the user-role associations
	if len(roleIds) > 0 {
		// Insert role assignments one by one
		for _, roleId := range roleIds {
			_, err = s.queries.CreateUserRole(ctx, iamdb.CreateUserRoleParams{
				UserID: userId,
				RoleID: roleId,
			})
			if err != nil {
				return iamdb.GetUserWithRolesRow{}, err
			}
		}
	}

	// Return the updated user with roles
	return s.queries.GetUserWithRoles(ctx, userId)
}

func (s *IamService) DeleteUser(ctx context.Context, userId uuid.UUID) error {
	// Check if user exists
	_, err := s.queries.GetUserWithRoles(ctx, userId)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return s.queries.DeleteUser(ctx, userId)
}
