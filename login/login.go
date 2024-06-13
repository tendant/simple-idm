package login

import (
	"context"
	"log/slog"

	"github.com/jinzhu/copier"
	"github.com/tendant/simple-user/login/db"
)

type LoginService struct {
	queries *db.Queries
}

func New(queries *db.Queries) *LoginService {
	return &LoginService{
		queries: queries,
	}
}

type ResetPasswordParams struct {
	Code string
	Password string
}

func (s LoginService) ResetPasswordUsers(ctx context.Context, params ResetPasswordParams) (error) {
	resetPasswordParams := db.ResetPasswordParams{}
	slog.Debug("resetPasswordParams", "params", params)
	copier.Copy(&resetPasswordParams, params)
	err := s.queries.ResetPassword(ctx, resetPasswordParams)
	return err
}
