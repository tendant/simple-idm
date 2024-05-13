package user

import "golang.org/x/exp/slog"

type UserService struct{}

type UserParams struct {
	Email string
}

func (s UserService) Create(params UserParams) {
	slog.Debug("Creating user use params:", "params", params)
}
