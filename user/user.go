package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/user/db"
	"golang.org/x/exp/slog"
)

type UserService struct {
	queries *db.Queries
}

func New(queries *db.Queries) *UserService {
	return &UserService{
		queries: queries,
	}
}

type UserParams struct {
	Email string
	Name  string
}

func (s UserService) Create(ctx context.Context, params UserParams) (db.User, error) {
	slog.Debug("Creating user use params:", "params", params)
	createUserParams := db.CreateUserParams{}
	copier.Copy(&createUserParams, params)
	user, err := s.queries.CreateUser(ctx, createUserParams)
	if err != nil {
		slog.Error("Failed creating user", "params", params, "err", err)
		return db.User{}, err
	}
	return user, err
}

func (s UserService) FindUsers(ctx context.Context) ([]db.User, error) {
	users, err := s.queries.FindUsers(ctx)
	return users, err
}

type UpdateUserParams struct {
	Uuid uuid.UUID
	Name string
}

func (s UserService) UpdateUsers(ctx context.Context, userParams UpdateUserParams) (db.User, error) {
	updateUserParams := db.UpdateUserParams{}
	slog.Debug("userParams service", "userParams", userParams)
	copier.Copy(&updateUserParams, userParams)
	user, err := s.queries.UpdateUser(ctx, updateUserParams)
	return user, err
}

func (s UserService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	slog.Debug("Deleting user with UUID:", "UUID", id)
	err := s.queries.DeleteUser(ctx, id)
	if err != nil {
		slog.Error("Failed deleting user", "UUID", id, "err", err)
	}
	return err
}

type GetUserUUIDParams struct {
	Uuid uuid.UUID
}

func (s UserService) GetUserUUID(ctx context.Context, userParams GetUserUUIDParams) (db.User, error) {
	getUserUUIDParams := GetUserUUIDParams{}
	slog.Debug("userParams service", "userParams", userParams)
	copier.Copy(&getUserUUIDParams, userParams)
	user, err := s.queries.GetUserUUID(ctx, getUserUUIDParams.Uuid)
	return user, err
}
