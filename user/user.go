package user

import (
	"context"

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
