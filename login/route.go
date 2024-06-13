package login

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/jinzhu/copier"
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

	if(data.Code == "" || data.Password == "") {
		slog.Error("Invalid Request." )
		return &Response{
			body: "Invalid Request.",
			Code: http.StatusBadRequest,
		}
	}

	// FIXME: hash/encode data.password, then write to database
	resetPasswordParams := PasswordReset{}
	copier.Copy(&resetPasswordParams, data)
	err = h.loginService.ResetPasswordUsers(r.Context(), resetPasswordParams)
	if err != nil {
		slog.Error("Failed updating password", data.Password, "err", err)
		return &Response{
			body: "Failed updating password",
			Code: http.StatusInternalServerError,
		}
	}

	return &Response{
		Code: http.StatusOK,
	}
}
