package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
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

type CreateUserRequest struct {
	Name      *string     `json:"name"`
	Email     string      `json:"email"`
	RoleUuids []uuid.UUID `json:"role_uuids"`
}

type UpdateUserRequest struct {
	Name      *string     `json:"name"`
	RoleUuids []uuid.UUID `json:"role_uuids"`
}

// Get a list of users
// (GET /users)
func (h Handle) GetUsers(w http.ResponseWriter, r *http.Request) *Response {
	users, err := h.userService.FindUsers(r.Context())
	if err != nil {
		slog.Error("Failed getting users", "error", err)
		return &Response{
			body: "Failed getting users",
			Code: http.StatusInternalServerError,
		}
	}

	var response []struct {
		Email *string `json:"email,omitempty"`
		Name  *string `json:"name,omitempty"`
		Roles []struct {
			Name *string `json:"name,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		} `json:"roles,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}
	for _, user := range users {
		uuidStr := user.Uuid.String()
		var namePtr *string
		if user.Name.Valid {
			namePtr = &user.Name.String
		}
		responseUser := struct {
			Email *string `json:"email,omitempty"`
			Name  *string `json:"name,omitempty"`
			Roles []struct {
				Name *string `json:"name,omitempty"`
				UUID *string `json:"uuid,omitempty"`
			} `json:"roles,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		}{
			Email: &user.Email,
			Name:  namePtr,
			UUID:  &uuidStr,
		}

		// Unmarshal roles from []byte
		var roles []struct {
			Name *string `json:"name,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		}
		if err := json.Unmarshal(user.Roles, &roles); err != nil {
			return &Response{
				body: fmt.Sprintf("Failed to unmarshal roles: %v", err),
				Code: http.StatusInternalServerError,
			}
		}
		responseUser.Roles = roles

		response = append(response, responseUser)
	}

	return &Response{
		body: response,
		Code: http.StatusOK,
	}
}

// Create a new user
// (POST /users)
func (h Handle) CreateUser(w http.ResponseWriter, r *http.Request) *Response {
	var request CreateUserRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		return &Response{
			body: "Invalid request body",
			Code: http.StatusBadRequest,
		}
	}

	if request.Email == "" {
		return &Response{
			body: "Email is required",
			Code: http.StatusBadRequest,
		}
	}

	var name string
	if request.Name != nil {
		name = *request.Name
	}

	user, err := h.userService.CreateUser(r.Context(), request.Email, name, request.RoleUuids)
	if err != nil {
		slog.Error("Failed creating user", "error", err)
		return &Response{
			body: "Failed creating user",
			Code: http.StatusInternalServerError,
		}
	}

	uuidStr := user.Uuid.String()
	var namePtr *string
	if user.Name.Valid {
		namePtr = &user.Name.String
	}
	responseUser := struct {
		Email *string `json:"email,omitempty"`
		Name  *string `json:"name,omitempty"`
		Roles []struct {
			Name *string `json:"name,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		} `json:"roles,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}{
		Email: &user.Email,
		Name:  namePtr,
		UUID:  &uuidStr,
	}

	// Unmarshal roles from []byte
	var roles []struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}
	if err := json.Unmarshal(user.Roles, &roles); err != nil {
		return &Response{
			body: fmt.Sprintf("Failed to unmarshal roles: %v", err),
			Code: http.StatusInternalServerError,
		}
	}
	responseUser.Roles = roles

	return &Response{
		body: responseUser,
		Code: http.StatusOK,
	}
}

// Get user details by UUID
// (GET /users/{uuid})
func (h Handle) GetUser(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	userUuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			body: "Invalid UUID format",
			Code: http.StatusBadRequest,
		}
	}

	user, err := h.userService.GetUser(r.Context(), userUuid)
	if err != nil {
		slog.Error("Failed getting user", "error", err)
		return &Response{
			body: "Failed getting user",
			Code: http.StatusInternalServerError,
		}
	}

	uuidStrPtr := user.Uuid.String()
	var namePtr *string
	if user.Name.Valid {
		namePtr = &user.Name.String
	}
	responseUser := struct {
		Email *string `json:"email,omitempty"`
		Name  *string `json:"name,omitempty"`
		Roles []struct {
			Name *string `json:"name,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		} `json:"roles,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}{
		Email: &user.Email,
		Name:  namePtr,
		UUID:  &uuidStrPtr,
	}

	// Unmarshal roles from []byte
	var roles []struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}
	if err := json.Unmarshal(user.Roles, &roles); err != nil {
		return &Response{
			body: fmt.Sprintf("Failed to unmarshal roles: %v", err),
			Code: http.StatusInternalServerError,
		}
	}
	responseUser.Roles = roles

	return &Response{
		body: responseUser,
		Code: http.StatusOK,
	}
}

// Update user details by UUID
// (PUT /users/{uuid})
func (h Handle) UpdateUser(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	userUuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			body: "Invalid UUID format",
			Code: http.StatusBadRequest,
		}
	}

	var request UpdateUserRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		return &Response{
			body: "Invalid request body",
			Code: http.StatusBadRequest,
		}
	}

	var name string
	if request.Name != nil {
		name = *request.Name
	}

	user, err := h.userService.UpdateUser(r.Context(), userUuid, name, request.RoleUuids)
	if err != nil {
		slog.Error("Failed updating user", "error", err)
		return &Response{
			body: "Failed updating user",
			Code: http.StatusInternalServerError,
		}
	}

	uuidStrPtr := user.Uuid.String()
	var namePtr *string
	if user.Name.Valid {
		namePtr = &user.Name.String
	}
	responseUser := struct {
		Email *string `json:"email,omitempty"`
		Name  *string `json:"name,omitempty"`
		Roles []struct {
			Name *string `json:"name,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		} `json:"roles,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}{
		Email: &user.Email,
		Name:  namePtr,
		UUID:  &uuidStrPtr,
	}

	// Unmarshal roles from []byte
	var roles []struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}
	if err := json.Unmarshal(user.Roles, &roles); err != nil {
		return &Response{
			body: fmt.Sprintf("Failed to unmarshal roles: %v", err),
			Code: http.StatusInternalServerError,
		}
	}
	responseUser.Roles = roles

	return &Response{
		body: responseUser,
		Code: http.StatusOK,
	}
}

// Delete user by UUID
// (DELETE /users/{uuid})
func (h Handle) DeleteUsersUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {
	userUuid, err := uuid.Parse(uuid)
	if err != nil {
		return &Response{
			body: "Invalid UUID format",
			Code: http.StatusBadRequest,
		}
	}

	err = h.userService.DeleteUser(r.Context(), userUuid)
	if err != nil {
		slog.Error("Failed deleting user", "error", err)
		return &Response{
			body: "Failed deleting user",
			Code: http.StatusInternalServerError,
		}
	}

	return &Response{
		body: "User deleted successfully",
		Code: http.StatusOK,
	}
}

func Routes(r *chi.Mux, handle Handle) {
	r.Group(func(r chi.Router) {
		// add auth middleware
		r.Mount("/", Handler(&handle))
	})
}
