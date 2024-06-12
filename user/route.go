package user

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"golang.org/x/exp/slog"
)

type Handle struct {
	userService *UserService
}

func NewHandle(userService *UserService) Handle {
	return Handle{
		userService: userService,
	}
}

// Get a list of users
// (GET /user)
func (h Handle) GetUser(w http.ResponseWriter, r *http.Request) *Response {
	dbUsers, err := h.userService.FindUsers(r.Context())
	if err != nil {
		slog.Error("Failed getting users err", err)
		return &Response{
			body: "Failed getting users",
			Code: http.StatusInternalServerError,
		}
	}
	return &Response{
		Code: http.StatusOK,
		body: dbUsers,
	}
}

// Create a new user
// (POST /user)
func (h Handle) PostUser(w http.ResponseWriter, r *http.Request) *Response {
	data := PostUserJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	slog.Debug("request params:", "data", data)

	userParams := UserParams{}
	copier.Copy(&userParams, data)
	dbUser, err := h.userService.Create(r.Context(), userParams)
	if err != nil {
		slog.Error("Failed creating user", userParams, "err", err)
		return &Response{
			body: "Failed creating user",
			Code: http.StatusInternalServerError,
		}
	}
	return &Response{
		Code: http.StatusCreated,
		body: dbUser,
	}
}

// FIXME: Delete user by UUID
// (DELETE /user/{uuid})
func (h Handle) DeleteUserUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {

	return nil
}

// FIXME: Get user details by UUID
// (GET /user/{uuid})
func (h Handle) GetUserUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		slog.Error("Invalid UUID format", "err", err)
		http.Error(w, "Invalid UUID format", http.StatusBadRequest)
		return nil
	}
	params := GetUserUUIDParams{
		Uuid: uuid,
	}
	user, err := h.userService.GetUserUUID(r.Context(), params)
	if err != nil {
		slog.Error("Failed getting user", "err", err)
		http.Error(w, "Failed getting user", http.StatusInternalServerError)
		return nil
	}
	return &Response{
		body:        user,
		Code:        200,
		contentType: "application/json",
	}
}

// FIXME: Update user details by UUID
// (PUT /user/{uuid})
func (h Handle) PutUserUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {
	return nil
}

func Routes(r *chi.Mux, handle Handle) {

	r.Group(func(r chi.Router) {
		// add auth middleware
		r.Mount("/api/v4", Handler(&handle))
	})
}
