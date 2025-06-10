package role

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tendant/simple-idm/pkg/role/roledb"
)

var (
	ErrEmptyRoleName = errors.New("role name cannot be empty")
	ErrRoleNotFound  = errors.New("role not found")
	ErrRoleHasUsers  = errors.New("cannot delete role that has users assigned")
)

// Domain models for the role repository

// Role represents a role in the domain model
type Role struct {
	ID   uuid.UUID
	Name string
}

// RoleUser represents a user assigned to a role
type RoleUser struct {
	ID        uuid.UUID
	Email     string
	Name      string
	NameValid bool
}

// UpdateRoleParams represents parameters for updating a role
type UpdateRoleParams struct {
	ID   uuid.UUID
	Name string
}

// RemoveUserFromRoleParams represents parameters for removing a user from a role
type RemoveUserFromRoleParams struct {
	UserID uuid.UUID
	RoleID uuid.UUID
}

// RoleRepository defines the interface for role data access
type RoleRepository interface {
	FindRoles(ctx context.Context) ([]Role, error)
	CreateRole(ctx context.Context, name string) (uuid.UUID, error)
	UpdateRole(ctx context.Context, arg UpdateRoleParams) error
	DeleteRole(ctx context.Context, id uuid.UUID) error
	GetRoleById(ctx context.Context, id uuid.UUID) (Role, error)
	GetRoleIdByName(ctx context.Context, name string) (uuid.UUID, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]RoleUser, error)
	HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error)
	RemoveUserFromRole(ctx context.Context, arg RemoveUserFromRoleParams) error
	AddUserToRole(ctx context.Context, roleID, userID uuid.UUID, username string) error
	WithTx(tx interface{}) RoleRepository
	WithPgxTx(tx pgx.Tx) RoleRepository
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
func (r *PostgresRoleRepository) FindRoles(ctx context.Context) ([]Role, error) {
	dbRoles, err := r.queries.FindRoles(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]Role, len(dbRoles))
	for i, dbRole := range dbRoles {
		roles[i] = Role{
			ID:   dbRole.ID,
			Name: dbRole.Name,
		}
	}

	return roles, nil
}

// CreateRole creates a new role
func (r *PostgresRoleRepository) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	return r.queries.CreateRole(ctx, name)
}

// UpdateRole updates an existing role
func (r *PostgresRoleRepository) UpdateRole(ctx context.Context, arg UpdateRoleParams) error {
	dbArg := roledb.UpdateRoleParams{
		ID:   arg.ID,
		Name: arg.Name,
	}
	return r.queries.UpdateRole(ctx, dbArg)
}

// DeleteRole deletes a role
func (r *PostgresRoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return r.queries.DeleteRole(ctx, id)
}

// GetRoleById retrieves a role by ID
func (r *PostgresRoleRepository) GetRoleById(ctx context.Context, id uuid.UUID) (Role, error) {
	dbRole, err := r.queries.GetRoleById(ctx, id)
	if err != nil {
		return Role{}, err
	}

	return Role{
		ID:   dbRole.ID,
		Name: dbRole.Name,
	}, nil
}

// GetRoleIdByName implements RoleRepository.
func (r *PostgresRoleRepository) GetRoleIdByName(ctx context.Context, name string) (uuid.UUID, error) {
	return r.queries.GetRoleIdByName(ctx, name)
}

// GetRoleUsers retrieves users assigned to a role
func (r *PostgresRoleRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]RoleUser, error) {
	dbUsers, err := r.queries.GetRoleUsers(ctx, roleID)
	if err != nil {
		return nil, err
	}

	users := make([]RoleUser, len(dbUsers))
	for i, dbUser := range dbUsers {
		users[i] = RoleUser{
			ID:        dbUser.ID,
			Email:     dbUser.Email,
			Name:      dbUser.Name.String,
			NameValid: dbUser.Name.Valid,
		}
	}

	return users, nil
}

// HasUsers checks if a role has users assigned
func (r *PostgresRoleRepository) HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error) {
	return r.queries.HasUsers(ctx, roleID)
}

// RemoveUserFromRole removes a user from a role
func (r *PostgresRoleRepository) RemoveUserFromRole(ctx context.Context, arg RemoveUserFromRoleParams) error {
	dbArg := roledb.RemoveUserFromRoleParams{
		UserID: arg.UserID,
		RoleID: arg.RoleID,
	}
	return r.queries.RemoveUserFromRole(ctx, dbArg)
}

// WithTx returns a new repository with the given transaction
func (r *PostgresRoleRepository) WithTx(tx interface{}) RoleRepository {
	switch v := tx.(type) {
	case pgx.Tx:
		return r.WithPgxTx(v)
	default:
		panic(fmt.Sprintf("unsupported transaction type: %v", tx))
	}
}

// WithPgxTx returns a new repository with the given pgx transaction
func (r *PostgresRoleRepository) WithPgxTx(tx pgx.Tx) RoleRepository {
	queries := r.queries.WithTx(tx)
	return &PostgresRoleRepository{
		queries: queries,
	}
}

// AddUserToRole adds a user to a role
func (r *PostgresRoleRepository) AddUserToRole(ctx context.Context, roleID, userID uuid.UUID, username string) error {
	_, err := r.queries.CreateUserRole(ctx, roledb.CreateUserRoleParams{
		UserID: userID,
		RoleID: roleID,
	})
	if err != nil {
		slog.Error("Failed to add user to role", "error", err)
		return err
	}
	return nil
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

func (s *RoleService) FindRoles(ctx context.Context) ([]Role, error) {
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

	return s.repo.UpdateRole(ctx, UpdateRoleParams{ID: id, Name: name})
}

// DeleteRole removes a role
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	// Check if role exists
	_, err := s.repo.GetRoleById(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrRoleNotFound) {
			// Role doesn't exist, which is fine for DELETE (idempotent)
			return nil
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
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (Role, error) {
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
func (s *RoleService) GetRoleUsers(ctx context.Context, id uuid.UUID) ([]RoleUser, error) {
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
	err = s.repo.RemoveUserFromRole(ctx, RemoveUserFromRoleParams{
		UserID: userID,
		RoleID: roleID,
	})
	if err != nil {
		return fmt.Errorf("error removing user from role: %w", err)
	}

	return nil
}

// AddUserToRole adds a user to a role
func (s *RoleService) AddUserToRole(ctx context.Context, roleID, userID uuid.UUID, username string) error {
	// Check if role exists
	_, err := s.repo.GetRoleById(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("error checking role existence: %w", err)
	}

	// Add user to role
	// This method relies on the repository implementing AddUserToRole
	err = s.repo.AddUserToRole(ctx, roleID, userID, username)
	if err != nil {
		return fmt.Errorf("error adding user to role: %w", err)
	}

	return nil
}

// GetRoleIdByName gets the role ID by name
func (s *RoleService) GetRoleIdByName(ctx context.Context, name string) (uuid.UUID, error) {
	return s.repo.GetRoleIdByName(ctx, name)
}
