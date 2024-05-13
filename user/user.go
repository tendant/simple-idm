package user

import (
	"context"

	"github.com/tendant/simple-user/user/db"
	"golang.org/x/exp/slog"
)

type UserService struct {
	queries *db.Queries
}

type UserParams struct {
	Email string
}

func (s UserService) Create(ctx context.Context, params UserParams) (db.User, error) {
	slog.Debug("Creating user use params:", "params", params)
	user, err := s.queries.CreateUser(ctx, params.Email)
	return user, err
}
