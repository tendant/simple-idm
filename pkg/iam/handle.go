package iam

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
	iamService *IamService
}

func NewHandle(iamService *IamService) Handle {
	return Handle{
		iamService: iamService,
	}
}

type CreateUserRequest struct {
	Name      *string     `json:"name"`
	Email     string      `json:"email"`
	Username  string      `json:"username"`
	RoleIds []uuid.UUID `json:"role_ids"`
}

type UpdateUserRequest struct {
	Name      *string     `json:"name"`
	RoleIds []uuid.UUID `json:"role_ids"`
}

// Get a list of users
// (GET /users)
func (h Handle) GetUsers(w http.ResponseWriter, r *http.Request) *Response {
	users, err := h.iamService.FindUsers(r.Context())
	if err != nil {
		slog.Error("Failed getting users", "error", err)
		return &Response{
			body: "Failed getting users",
			Code: http.StatusInternalServerError,
		}
	}

	var response []struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID *string `json:"id,omitempty"`
	}

	for _, user := range users {
		idStr := user.ID.String()
		var namePtr *string
		if user.Name.Valid {
			namePtr = &user.Name.String
		}

		// Handle roles
		var roles []struct {
			Name *string `json:"name,omitempty"`
			ID *string `json:"id,omitempty"`
		}
		if len(user.Roles) > 0 {
			err := json.Unmarshal(user.Roles, &roles)
			if err != nil {
				slog.Error("Failed to unmarshal roles", "error", err)
				continue
			}
		}

		response = append(response, struct {
			Email    *string `json:"email,omitempty"`
			Username *string `json:"username,omitempty"`
			Name     *string `json:"name,omitempty"`
			Roles    []struct {
				Name *string `json:"name,omitempty"`
				ID *string `json:"id,omitempty"`
			} `json:"roles,omitempty"`
			ID *string `json:"id,omitempty"`
		}{
			Email:    &user.Email,
			Username: &user.Username.String,
			Name:     namePtr,
			Roles:    roles,
			ID:     &idStr,
		})
	}

	return &Response{
		Code: http.StatusOK,
		body: response,
	}
}

// Create a new user
// (POST /users)
func (h Handle) PostUsers(w http.ResponseWriter, r *http.Request) *Response {
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

	if request.Username == "" {
		return &Response{
			body: "Username is required",
			Code: http.StatusBadRequest,
		}
	}

	var name string
	if request.Name != nil {
		name = *request.Name
	}

	user, err := h.iamService.CreateUser(r.Context(), request.Email, request.Username, name, request.RoleIds)
	if err != nil {
		slog.Error("Failed creating user", "error", err)
		return &Response{
			body: "Failed creating user",
			Code: http.StatusInternalServerError,
		}
	}

	idStr := user.ID.String()
	var namePtr *string
	if user.Name.Valid {
		namePtr = &user.Name.String
	}
	var usernamePtr *string
	if user.Username.Valid {
		usernamePtr = &user.Username.String
	}
	responseUser := struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID *string `json:"id,omitempty"`
	}{
		Email:    &user.Email,
		Username: usernamePtr,
		Name:     namePtr,
		ID:     &idStr,
	}

	// Unmarshal roles from []byte
	var roles []struct {
		Name *string `json:"name,omitempty"`
		ID *string `json:"id,omitempty"`
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
func (h Handle) GetUsersUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	userUuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			body: "Invalid UUID format",
			Code: http.StatusBadRequest,
		}
	}

	user, err := h.iamService.GetUser(r.Context(), userUuid)
	if err != nil {
		slog.Error("Failed getting user", "error", err)
		return &Response{
			body: "Failed getting user",
			Code: http.StatusInternalServerError,
		}
	}

	idStrPtr := user.ID.String()
	var namePtr *string
	if user.Name.Valid {
		namePtr = &user.Name.String
	}
	var usernamePtr *string
	if user.Username.Valid {
		usernamePtr = &user.Username.String
	}
	responseUser := struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID *string `json:"id,omitempty"`
	}{
		Email:    &user.Email,
		Username: usernamePtr,
		Name:     namePtr,
		ID:     &idStrPtr,
	}

	// Unmarshal roles from []byte
	var roles []struct {
		Name *string `json:"name,omitempty"`
		ID *string `json:"id,omitempty"`
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
func (h Handle) PutUsersUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
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

	user, err := h.iamService.UpdateUser(r.Context(), userUuid, name, request.RoleIds)
	if err != nil {
		slog.Error("Failed updating user", "error", err)
		return &Response{
			body: "Failed updating user",
			Code: http.StatusInternalServerError,
		}
	}

	idStrPtr := user.ID.String()
	var namePtr *string
	if user.Name.Valid {
		namePtr = &user.Name.String
	}
	var usernamePtr *string
	if user.Username.Valid {
		usernamePtr = &user.Username.String
	}
	responseUser := struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID *string `json:"id,omitempty"`
	}{
		Email:    &user.Email,
		Username: usernamePtr,
		Name:     namePtr,
		ID:     &idStrPtr,
	}

	// Unmarshal roles from []byte
	var roles []struct {
		Name *string `json:"name,omitempty"`
		ID *string `json:"id,omitempty"`
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
func (h Handle) DeleteUsersUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	userUuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			body: "Invalid UUID format",
			Code: http.StatusBadRequest,
		}
	}

	err = h.iamService.DeleteUser(r.Context(), userUuid)
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
		r.Mount("/idm", Handler(&handle))
	})
}
