package login

import (
	"context"

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

type LoginParams struct {
	Email string
}

func (s LoginService) Login(ctx context.Context, params LoginParams) (db.FindUserRow, error) {
	user, err := s.queries.FindUser(ctx, params.Email)
	return user, err
}
