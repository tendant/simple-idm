package role

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tendant/simple-idm/pkg/role/roledb"
	"github.com/google/uuid"
)

var (
	ErrEmptyRoleName = errors.New("role name cannot be empty")
	ErrRoleNotFound  = errors.New("role not found")
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
	_, err := s.queries.GetRoleUUID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return err
	}

	return s.queries.UpdateRole(ctx, roledb.UpdateRoleParams{Uuid: id, Name: name})
}

// DeleteRole removes a role
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return s.queries.DeleteRole(ctx, id)
}

// GetRole retrieves a role by UUID
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (roledb.GetRoleUUIDRow, error) {
	role, err := s.queries.GetRoleUUID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return role, ErrRoleNotFound
		}
		return role, err
	}
	return role, nil
}
