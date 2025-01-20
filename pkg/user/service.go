package user

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/user/db"
)

type UserService struct {
	queries *db.Queries
}

func NewUserService(queries *db.Queries) *UserService {
	return &UserService{
		queries: queries,
	}
}

func (s *UserService) CreateUser(ctx context.Context, email, name string, roleUuids []uuid.UUID) (db.GetUserWithRolesRow, error) {
	// Create the user first
	nullString := sql.NullString{String: name, Valid: name != ""}
	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Email: email,
		Name:  nullString,
	})
	if err != nil {
		return db.GetUserWithRolesRow{}, err
	}

	// If there are roles to assign, create the user-role associations
	if len(roleUuids) > 0 {
		// Prepare the role assignments
		roleAssignments := make([]db.CreateUserRoleBatchParams, len(roleUuids))
		for i, roleUuid := range roleUuids {
			roleAssignments[i] = db.CreateUserRoleBatchParams{
				UserUuid: user.Uuid,
				RoleUuid: roleUuid,
			}
		}

		// Batch insert the role assignments
		_, err = s.queries.CreateUserRoleBatch(ctx, roleAssignments)
		if err != nil {
			return db.GetUserWithRolesRow{}, err
		}
	}

	// Get the user with roles
	return s.queries.GetUserWithRoles(ctx, user.Uuid)
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
		// Prepare the role assignments
		roleAssignments := make([]db.CreateUserRoleBatchParams, len(roleUuids))
		for i, roleUuid := range roleUuids {
			roleAssignments[i] = db.CreateUserRoleBatchParams{
				UserUuid: userUuid,
				RoleUuid: roleUuid,
			}
		}

		// Batch insert the role assignments
		_, err = s.queries.CreateUserRoleBatch(ctx, roleAssignments)
		if err != nil {
			return db.GetUserWithRolesRow{}, err
		}
	}

	// Return the updated user with roles
	return s.queries.GetUserWithRoles(ctx, userUuid)
}

func (s *UserService) DeleteUser(ctx context.Context, userUuid uuid.UUID) error {
	return s.queries.DeleteUser(ctx, userUuid)
}
