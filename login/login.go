package login

import (
	"context"

	"github.com/jinzhu/copier"
	"github.com/tendant/simple-user/login/db"
	"golang.org/x/exp/slog"
)

type LoginService struct {
	queries *db.Queries
}

func New(queries *db.Queries) *LoginService {
	return &LoginService{
		queries: queries,
	}
}

type RegisterParam struct {
	Email    string
	Name     string
	Password string
}

func (s LoginService) Create(ctx context.Context, params RegisterParam) (db.User, error) {
	slog.Debug("Registering user use params:", "params", params)
	registerRequest := db.RegisterUserParams{}
	copier.Copy(&registerRequest, params)
	user, err := s.queries.RegisterUser(ctx, registerRequest)
	if err != nil {
		slog.Error("Failed to register user", "params", params, "err", err)
		return db.User{}, err
	}
	return user, err
}
