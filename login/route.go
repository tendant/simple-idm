package login

import (
	"crypto/sha256"
	"encoding/json"
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
	var body PostPasswordResetInitJSONBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		slog.Error("Failed extracting this email", "err", err)
		http.Error(w, "Failed extracting this email", http.StatusBadRequest)
		return nil
	}
	if body.Email != nil {
		email := string(*body.Email)
		uuid, err := h.loginService.queries.InitPassword(r.Context(), email)
		if err != nil {
			slog.Error("Failed finding user of this email", "err", err)
			http.Error(w, "Failed finding user of this email", http.StatusBadRequest)
			return nil
		}

		hash := sha256.New()
		hash.Write([]byte(uuid.String()))
		code := hash.Sum(nil)
		slog.Info("generated code", "code", code)
		return &Response{
			body:        code,
			Code:        200,
			contentType: "application/json",
		}

	} else {
		slog.Error("Email is missing in the request body", "err", err)
		http.Error(w, "Failed finding user of this email", http.StatusBadRequest)
		return nil
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
