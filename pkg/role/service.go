package role

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/role/roledb"
)

var (
	ErrEmptyRoleName = errors.New("role name cannot be empty")
	ErrRoleNotFound  = errors.New("role not found")
	ErrRoleHasUsers  = errors.New("cannot delete role that has users assigned")
)

// RoleService provides methods for role management
type RoleService struct {
	queries *roledb.Queries
}

func NewRoleService(queries *roledb.Queries) *RoleService {
	return &RoleService{
		queries: queries,
	}
}

func (s *RoleService) FindRoles(ctx context.Context) ([]roledb.FindRolesRow, error) {
	return s.queries.FindRoles(ctx)
}

// CreateRole adds a new role
func (s *RoleService) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	if name == "" {
		return uuid.Nil, ErrEmptyRoleName
	}
	return s.queries.CreateRole(ctx, name)
}

// UpdateRole modifies an existing role
func (s *RoleService) UpdateRole(ctx context.Context, id uuid.UUID, name string) error {
	if name == "" {
		return ErrEmptyRoleName
	}

	// Check if role exists
	_, err := s.queries.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return err
	}

	return s.queries.UpdateRole(ctx, roledb.UpdateRoleParams{ID: id, Name: name})
}

// DeleteRole removes a role
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	// Check if role exists
	_, err := s.queries.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("error checking role existence: %w", err)
	}

	// Check if role has any users
	hasUsers, err := s.queries.HasUsers(ctx, id)
	if err != nil {
		return fmt.Errorf("error checking if role has users: %w", err)
	}
	if hasUsers {
		return ErrRoleHasUsers
	}

	// Delete the role
	err = s.queries.DeleteRole(ctx, id)
	if err != nil {
		return fmt.Errorf("error deleting role: %w", err)
	}

	return nil
}

// GetRole retrieves a role by UUID
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (roledb.GetRoleByIdRow, error) {
	role, err := s.queries.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return role, ErrRoleNotFound
		}
		return role, err
	}
	return role, nil
}

// GetRoleUsers retrieves all users assigned to a role
func (s *RoleService) GetRoleUsers(ctx context.Context, id uuid.UUID) ([]roledb.GetRoleUsersRow, error) {
	// Check if role exists
	_, err := s.queries.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("error checking role existence: %w", err)
	}

	users, err := s.queries.GetRoleUsers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting role users: %w", err)
	}

	return users, nil
}

// RemoveUserFromRole removes a user from a role
func (s *RoleService) RemoveUserFromRole(ctx context.Context, roleID, userID uuid.UUID) error {
	// Check if role exists
	_, err := s.queries.GetRoleById(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("error checking role existence: %w", err)
	}

	// Remove user from role
	err = s.queries.RemoveUserFromRole(ctx, roledb.RemoveUserFromRoleParams{
		UserID: userID,
		RoleID: roleID,
	})
	if err != nil {
		return fmt.Errorf("error removing user from role: %w", err)
	}

	return nil
}
