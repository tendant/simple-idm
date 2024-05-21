package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-user/user/db"
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
}

func (s UserService) Create(ctx context.Context, params UserParams) (db.User, error) {
	slog.Debug("Creating user use params:", "params", params)
	user, err := s.queries.CreateUser(ctx, params.Email)
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
	Uuid  uuid.UUID
	Email string
}

func (s UserService) UpdateUsers(ctx context.Context, userParams UpdateUserParams) (db.User, error) {
	updateUserParams := db.UpdateUserParams{}
	slog.Debug("userParams service", "userParams", userParams)
	copier.Copy(&updateUserParams, userParams)
	user, err := s.queries.UpdateUser(ctx, updateUserParams)
	return user, err
}
