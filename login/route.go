package login

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
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
