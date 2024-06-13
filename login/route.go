package login

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/tendant/simple-user/auth"
)

type Handle struct {
	loginService *LoginService
}

func NewHandle(loginService *LoginService) Handle {
	return Handle{
		loginService: loginService,
	}
}

func Routes(r *chi.Mux, handle Handle) {

	r.Group(func(r chi.Router) {
		// add auth middleware
		r.Mount("/api/v4", Handler(&handle))
	})
}

func (h Handle) PostLogin(w http.ResponseWriter, r *http.Request) *Response {
	return &Response{
		Code: http.StatusNotImplemented,
	}

}

func (h Handle) PostPasswordResetInit(w http.ResponseWriter, r *http.Request) *Response {

	// FIXME: create random code
	code := "random code"

	// FIXME: email code to user
	slog.Info("generated code", "code", code)

	return &Response{
		Code: http.StatusOK,
	}
}

func (h Handle) PostPasswordReset(w http.ResponseWriter, r *http.Request) *Response {

	data := PostPasswordResetJSONBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// FIXME: validate data.code
	slog.Info("password reset", "data", data)

	// FIXME: hash/encode data.password, then write to database

	return &Response{
		Code: http.StatusOK,
	}
}

func (h Handle) GetTokenRefresh(w http.ResponseWriter, r *http.Request, params GetTokenRefreshParams) *Response {

	// FIXME: validate refreshToken
	jwt := auth.Jwt{}
	accessToken, err := jwt.CreateAccessToken("")
	if err != nil {
		slog.Error("Failed to create access token", params.RefreshToken, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := jwt.CreateAccessToken("")
	if err != nil {
		slog.Error("Failed to create refresh token", params.RefreshToken, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	result := Tokens{
		AccessToken: &accessToken,
		RefreshToken: &refreshToken,
	}

	return &Response{
		Code: http.StatusOK,
		body: result,
	}
}