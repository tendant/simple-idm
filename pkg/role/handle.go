package role

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type Handle struct {
	roleService *RoleService
}

func NewHandle(roleService *RoleService) *Handle {
	return &Handle{
		roleService: roleService,
	}
}

// Get handles retrieving a list of roles
func (h *Handle) Get(w http.ResponseWriter, r *http.Request) *Response {
	roles, err := h.roleService.FindRoles(r.Context())
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to find roles: %v", err),
		}
	}

	apiRoles := make([]struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}, len(roles))

	for i, role := range roles {
		name := role.Name             // Create a new variable to get the address
		uuidStr := role.Uuid.String() // Convert UUID to string
		apiRoles[i] = struct {
			Name *string `json:"name,omitempty"`
			UUID *string `json:"uuid,omitempty"`
		}{
			Name: &name,
			UUID: &uuidStr,
		}
	}

	return GetJSON200Response(apiRoles)
}

// GetUUID handles retrieving a role by UUID
func (h *Handle) GetUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	role, err := h.roleService.GetRole(r.Context(), roleUUID)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return &Response{
				Code: http.StatusNotFound,
				body: fmt.Sprintf("role not found: %v", err),
			}
		}
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to find role: %v", err),
		}
	}

	name := role.Name             // Create a new variable to get the address
	uuid := role.Uuid.String() // Convert UUID to string

	return GetUUIDJSON200Response(struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}{
		Name: &name,
		UUID: &uuid,
	})
}

// GetUUIDUsers handles retrieving users assigned to a role
func (h *Handle) GetUUIDUsers(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	users, err := h.roleService.GetRoleUsers(r.Context(), roleUUID)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return &Response{
				Code: http.StatusNotFound,
				body: fmt.Sprintf("role not found: %v", err),
			}
		}
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to get role users: %v", err),
		}
	}

	// Convert to API format
	apiUsers := make([]struct {
		UUID     *string `json:"uuid,omitempty"`
		Email    *string `json:"email,omitempty"`
		Name     *string `json:"name,omitempty"`
		Username *string `json:"username,omitempty"`
	}, len(users))

	for i, user := range users {
		uuid := user.Uuid.String()
		email := user.Email
		name := user.Name.String
		username := user.Username.String

		apiUsers[i] = struct {
			UUID     *string `json:"uuid,omitempty"`
			Email    *string `json:"email,omitempty"`
			Name     *string `json:"name,omitempty"`
			Username *string `json:"username,omitempty"`
		}{
			UUID:     &uuid,
			Email:    &email,
			Name:     &name,
			Username: &username,
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: apiUsers,
	}
}

// Post handles the creation of a new role
func (h *Handle) Post(w http.ResponseWriter, r *http.Request) *Response {
	var requestBody PostJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("failed to decode request body: %v", err),
		}
	}

	if requestBody.Name == nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "name is required",
		}
	}

	roleUUID, err := h.roleService.CreateRole(r.Context(), *requestBody.Name)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to create role: %v", err),
		}
	}

	uuidStr := roleUUID.String()

	return &Response{
		Code: http.StatusCreated,
		body: struct {
			UUID *string `json:"uuid,omitempty"`
			Name *string `json:"name,omitempty"`
		}{
			UUID: &uuidStr,
			Name: requestBody.Name,
		},
	}
}

// PutUUID handles updating an existing role
func (h *Handle) PutUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	var requestBody struct {
		Name *string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("failed to decode request body: %v", err),
		}
	}

	if requestBody.Name == nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "name is required",
		}
	}

	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	err = h.roleService.UpdateRole(r.Context(), roleUUID, *requestBody.Name)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return &Response{
				Code: http.StatusNotFound,
				body: fmt.Sprintf("role not found: %v", err),
			}
		}
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to update role: %v", err),
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: struct {
			UUID *string `json:"uuid,omitempty"`
			Name *string `json:"name,omitempty"`
		}{
			UUID: &uuidStr,
			Name: requestBody.Name,
		},
	}
}

// DeleteUUID handles deleting a role
func (h *Handle) DeleteUUID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	err = h.roleService.DeleteRole(r.Context(), roleUUID)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return &Response{
				Code: http.StatusNotFound,
				body: fmt.Sprintf("role not found: %v", err),
			}
		}
		if errors.Is(err, ErrRoleHasUsers) {
			return &Response{
				Code: http.StatusBadRequest,
				body: "Cannot delete role that has users assigned. Please remove all users from the role first.",
			}
		}
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to delete role: %v", err),
		}
	}

	return &Response{
		Code: http.StatusNoContent,
	}
}
