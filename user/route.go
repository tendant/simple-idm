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

// FIXME: Get a list of users
// (GET /user)
func (h Handle) GetUser(w http.ResponseWriter, r *http.Request) *Response {
	return nil
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
func (h Handle) DeleteUserUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	id, err := uuid.Parse(uuidStr)
	if err != nil {
		slog.Error("Error when parsing string to uuid", "uuid", uuidStr, "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Error when parsing string to uuid",
		}
	}
	err = h.userService.DeleteUser(r.Context(), id)
	if err != nil {
		slog.Error("Failed to delete user", "uuid", uuidStr, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to delete user",
		}
	}
	return &Response{
		Code: http.StatusOK,
		
	}
}

// FIXME: Get user details by UUID
// (GET /user/{uuid})
func (h Handle) GetUserUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {
	return nil
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
