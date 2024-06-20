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

type LoginParams struct {
	Email string
}

func (s LoginService) Login(ctx context.Context, params LoginParams) (db.FindUserRow, error) {
	user, err := s.queries.FindUser(ctx, params.Email)
	return user, err
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

func (s LoginService) EmailVerify(ctx context.Context, param string) error {
	slog.Debug("Verifying user use params:", "params", param)
	err := s.queries.EmailVerify(ctx, param)
	if err != nil {
		slog.Error("Failed to verify user", "params", param, "err", err)
		return err
	}
	return nil
}

func (s LoginService) ResetPasswordUsers(ctx context.Context, params PasswordReset) (error) {
	resetPasswordParams := db.ResetPasswordParams{}
	slog.Debug("resetPasswordParams", "params", params)
	copier.Copy(&resetPasswordParams, params)
	err := s.queries.ResetPassword(ctx, resetPasswordParams)
	return err
}
