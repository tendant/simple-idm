package iam

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam/db"
)

type UserService struct {
	queries *db.Queries
}

func NewUserService(queries *db.Queries) *UserService {
	return &UserService{
		queries: queries,
	}
}

func (s *UserService) CreateUser(ctx context.Context, email, username, name string, roleUuids []uuid.UUID) (db.GetUserWithRolesRow, error) {
	// Validate email
	if email == "" {
		return db.GetUserWithRolesRow{}, fmt.Errorf("email is required")
	}
	// Validate username
	if username == "" {
		return db.GetUserWithRolesRow{}, fmt.Errorf("username is required")
	}

	// Create the user first
	nullString := sql.NullString{String: name, Valid: name != ""}
	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Email:    email,
		Username: sql.NullString{String: username, Valid: true},
		Name:     nullString,
	})
	if err != nil {
		return db.GetUserWithRolesRow{}, fmt.Errorf("failed to create user: %w", err)
	}

	// If there are roles to assign, create the user-role associations
	if len(roleUuids) > 0 {
		// Insert role assignments one by one
		for _, roleUuid := range roleUuids {
			_, err = s.queries.CreateUserRole(ctx, db.CreateUserRoleParams{
				UserUuid: user.Uuid,
				RoleUuid: roleUuid,
			})
			if err != nil {
				return db.GetUserWithRolesRow{}, fmt.Errorf("failed to assign role: %w", err)
			}
		}
	}

	// Get the user with roles
	userWithRoles, err := s.queries.GetUserWithRoles(ctx, user.Uuid)
	if err != nil {
		return db.GetUserWithRolesRow{}, fmt.Errorf("failed to get user with roles: %w", err)
	}

	return userWithRoles, nil
}

func (s *UserService) FindUsers(ctx context.Context) ([]db.FindUsersWithRolesRow, error) {
	return s.queries.FindUsersWithRoles(ctx)
}

func (s *UserService) GetUser(ctx context.Context, userUuid uuid.UUID) (db.GetUserWithRolesRow, error) {
	return s.queries.GetUserWithRoles(ctx, userUuid)
}

func (s *UserService) UpdateUser(ctx context.Context, userUuid uuid.UUID, name string, roleUuids []uuid.UUID) (db.GetUserWithRolesRow, error) {
	// Update the user's name
	nullString := sql.NullString{String: name, Valid: name != ""}
	_, err := s.queries.UpdateUser(ctx, db.UpdateUserParams{
		Uuid: userUuid,
		Name: nullString,
	})
	if err != nil {
		return db.GetUserWithRolesRow{}, err
	}

	// Delete existing roles
	err = s.queries.DeleteUserRoles(ctx, userUuid)
	if err != nil {
		return db.GetUserWithRolesRow{}, err
	}

	// If there are new roles to assign, create the user-role associations
	if len(roleUuids) > 0 {
		// Insert role assignments one by one
		for _, roleUuid := range roleUuids {
			_, err = s.queries.CreateUserRole(ctx, db.CreateUserRoleParams{
				UserUuid: userUuid,
				RoleUuid: roleUuid,
			})
			if err != nil {
				return db.GetUserWithRolesRow{}, err
			}
		}
	}

	// Return the updated user with roles
	return s.queries.GetUserWithRoles(ctx, userUuid)
}

func (s *UserService) DeleteUser(ctx context.Context, userUuid uuid.UUID) error {
	// Check if user exists
	_, err := s.queries.GetUserWithRoles(ctx, userUuid)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return s.queries.DeleteUser(ctx, userUuid)
}
