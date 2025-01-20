package db

import (
	"context"

	"github.com/google/uuid"
)

type Querier interface {
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	CreateUserRole(ctx context.Context, arg CreateUserRoleParams) (UserRole, error)
	DeleteUser(ctx context.Context, uuid uuid.UUID) error
	DeleteUserRoles(ctx context.Context, userUuid uuid.UUID) error
	FindUsers(ctx context.Context) ([]FindUsersRow, error)
	FindUsersWithRoles(ctx context.Context) ([]FindUsersWithRolesRow, error)
	GetUserUUID(ctx context.Context, uuid uuid.UUID) (GetUserUUIDRow, error)
	GetUserWithRoles(ctx context.Context, uuid uuid.UUID) (GetUserWithRolesRow, error)
	UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error)
}
