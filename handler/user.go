package handler

import (
	"net/http"

	"github.com/ggicci/httpin"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-user/user"
	"golang.org/x/exp/slog"
)

type Handler struct {
	UserService *user.UserService
}

func (h *Handler) Routes(r *chi.Mux) {
	r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, http.StatusText(http.StatusOK))
	})

	r.With(httpin.NewInput(UserInput{})).Post("/api/users", h.handleCreateUser)
	r.With(httpin.NewInput(UserInput{})).Put("/api/users", h.handleUpdateUser)
	r.Get("/api/users", h.handleFindUsers)
}

type UserParams struct {
	Uuid  string `json:"uuid"`
	Email string `json:"email"`
}

type UserInput struct {
	Payload *UserParams `in:"body=json"`
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	slog.Debug("debug ***")
	input := r.Context().Value(httpin.Input).(*UserInput)
	slog.Debug("input ****:", "input", input, "user params", input.Payload)
	params := input.Payload
	userParams := user.UserParams{}
	copier.Copy(&userParams, params)
	// svc := user.UserService{}
	user, err := h.UserService.Create(r.Context(), userParams)
	if err != nil {
		slog.Error("Falied creating users", "err", err)
		http.Error(w, "Failed creating users", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, user)
}

func (h *Handler) handleFindUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.UserService.FindUsers(r.Context())
	if err != nil {
		slog.Error("Failed finding users:", "err", err)
		http.Error(w, "Failed finding users", http.StatusInternalServerError)
		return
	}
	slog.Debug("users:", "users", users)
	render.JSON(w, r, users)
}

func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	input := r.Context().Value(httpin.Input).(*UserInput)
	params := input.Payload
	userParams := user.UpdateUserParams{}
	copier.Copy(&userParams, params)
	user, err := h.UserService.UpdateUsers(r.Context(), userParams)
	if err != nil {
		slog.Error("Failed updating user", "err", err)
		http.Error(w, "Failed updating user", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, user)
}
