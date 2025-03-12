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

// RoleRepository defines the interface for role data access
type RoleRepository interface {
	FindRoles(ctx context.Context) ([]roledb.FindRolesRow, error)
	CreateRole(ctx context.Context, name string) (uuid.UUID, error)
	UpdateRole(ctx context.Context, arg roledb.UpdateRoleParams) error
	DeleteRole(ctx context.Context, id uuid.UUID) error
	GetRoleById(ctx context.Context, id uuid.UUID) (roledb.GetRoleByIdRow, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]roledb.GetRoleUsersRow, error)
	HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error)
	RemoveUserFromRole(ctx context.Context, arg roledb.RemoveUserFromRoleParams) error
}

// PostgresRoleRepository implements RoleRepository using roledb.Queries
type PostgresRoleRepository struct {
	queries *roledb.Queries
}

// NewPostgresRoleRepository creates a new PostgresRoleRepository
func NewPostgresRoleRepository(queries *roledb.Queries) *PostgresRoleRepository {
	return &PostgresRoleRepository{
		queries: queries,
	}
}

// FindRoles returns all roles
func (r *PostgresRoleRepository) FindRoles(ctx context.Context) ([]roledb.FindRolesRow, error) {
	return r.queries.FindRoles(ctx)
}

// CreateRole creates a new role
func (r *PostgresRoleRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	return r.queries.CreateRole(ctx, name)
}

// UpdateRole updates an existing role
func (r *PostgresRoleRepository) UpdateRole(ctx context.Context, arg roledb.UpdateRoleParams) error {
	return r.queries.UpdateRole(ctx, arg)
}

// DeleteRole deletes a role
func (r *PostgresRoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteRole(ctx, id)
}

// GetRoleById retrieves a role by ID
func (r *PostgresRoleRepository) GetRoleById(ctx context.Context, id uuid.UUID) (roledb.GetRoleByIdRow, error) {
	return r.queries.GetRoleById(ctx, id)
}

// GetRoleUsers retrieves users assigned to a role
func (r *PostgresRoleRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]roledb.GetRoleUsersRow, error) {
	return r.queries.GetRoleUsers(ctx, roleID)
}

// HasUsers checks if a role has users assigned
func (r *PostgresRoleRepository) HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error) {
	return r.queries.HasUsers(ctx, roleID)
}

// RemoveUserFromRole removes a user from a role
func (r *PostgresRoleRepository) RemoveUserFromRole(ctx context.Context, arg roledb.RemoveUserFromRoleParams) error {
	return r.queries.RemoveUserFromRole(ctx, arg)
}

// RoleService provides methods for role management
type RoleService struct {
	repo RoleRepository
}

// NewRoleService creates a new RoleService
func NewRoleService(repo RoleRepository) *RoleService {
	return &RoleService{
		repo: repo,
	}
}

func (s *RoleService) FindRoles(ctx context.Context) ([]roledb.FindRolesRow, error) {
	return s.repo.FindRoles(ctx)
}

// CreateRole adds a new role
func (s *RoleService) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	if name == "" {
		return uuid.Nil, ErrEmptyRoleName
	}
	return s.repo.CreateRole(ctx, name)
}

// UpdateRole modifies an existing role
func (s *RoleService) UpdateRole(ctx context.Context, id uuid.UUID, name string) error {
	if name == "" {
		return ErrEmptyRoleName
	}

	// Check if role exists
	_, err := s.repo.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return err
	}

	return s.repo.UpdateRole(ctx, roledb.UpdateRoleParams{ID: id, Name: name})
}

// DeleteRole removes a role
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	// Check if role exists
	_, err := s.repo.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("error checking role existence: %w", err)
	}

	// Check if role has any users
	hasUsers, err := s.repo.HasUsers(ctx, id)
	if err != nil {
		return fmt.Errorf("error checking if role has users: %w", err)
	}
	if hasUsers {
		return ErrRoleHasUsers
	}

	// Delete the role
	err = s.repo.DeleteRole(ctx, id)
	if err != nil {
		return fmt.Errorf("error deleting role: %w", err)
	}

	return nil
}

// GetRole retrieves a role by UUID
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (roledb.GetRoleByIdRow, error) {
	role, err := s.repo.GetRoleById(ctx, id)
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
	_, err := s.repo.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("error checking role existence: %w", err)
	}

	users, err := s.repo.GetRoleUsers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting role users: %w", err)
	}

	return users, nil
}

// RemoveUserFromRole removes a user from a role
func (s *RoleService) RemoveUserFromRole(ctx context.Context, roleID, userID uuid.UUID) error {
	// Check if role exists
	_, err := s.repo.GetRoleById(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("error checking role existence: %w", err)
	}

	// Remove user from role
	err = s.repo.RemoveUserFromRole(ctx, roledb.RemoveUserFromRoleParams{
		UserID: userID,
		RoleID: roleID,
	})
	if err != nil {
		return fmt.Errorf("error removing user from role: %w", err)
	}

	return nil
}
