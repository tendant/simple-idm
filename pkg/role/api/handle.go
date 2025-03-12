package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	rolepkg "github.com/tendant/simple-idm/pkg/role"
)

type Handle struct {
	roleService *rolepkg.RoleService
}

func NewHandle(roleService *rolepkg.RoleService) *Handle {
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
		ID   *string `json:"id,omitempty"`
		Name *string `json:"name,omitempty"`
	}, len(roles))

	for i, role := range roles {
		name := role.Name           // Create a new variable to get the address
		uuidStr := role.ID.String() // Convert UUID to string
		apiRoles[i] = struct {
			ID   *string `json:"id,omitempty"`
			Name *string `json:"name,omitempty"`
		}{
			ID:   &uuidStr,
			Name: &name,
		}
	}

	return GetJSON200Response(apiRoles)
}

// GetID handles retrieving a role by UUID
func (h *Handle) GetID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	roleData, err := h.roleService.GetRole(r.Context(), roleUUID)
	if err != nil {
		if errors.Is(err, rolepkg.ErrRoleNotFound) {
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

	name := roleData.Name          // Create a new variable to get the address
	uuidStr = roleData.ID.String() // Convert UUID to string

	return GetIDJSON200Response(struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}{
		Name: &name,
		UUID: &uuidStr,
	})
}

// GetIDUsers handles retrieving users assigned to a role
func (h *Handle) GetIDUsers(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	users, err := h.roleService.GetRoleUsers(r.Context(), roleUUID)
	if err != nil {
		if errors.Is(err, rolepkg.ErrRoleNotFound) {
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
		Email *string `json:"email,omitempty"`
		ID    *string `json:"id,omitempty"`
		Name  *string `json:"name,omitempty"`
	}, len(users))

	for i, user := range users {
		id := user.ID.String()
		email := user.Email
		var name string
		if user.NameValid {
			name = user.Name
		}

		apiUsers[i] = struct {
			Email *string `json:"email,omitempty"`
			ID    *string `json:"id,omitempty"`
			Name  *string `json:"name,omitempty"`
		}{
			Email: &email,
			ID:    &id,
			Name:  &name,
		}
	}

	return GetIDUsersJSON200Response(apiUsers)
}

// DeleteIDUsersUserID handles removing a user from a role
func (h *Handle) DeleteIDUsersUserID(w http.ResponseWriter, r *http.Request, uuidStr string, userUuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid role UUID format: %v", err),
		}
	}

	userUUID, err := uuid.Parse(userUuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid user UUID format: %v", err),
		}
	}

	err = h.roleService.RemoveUserFromRole(r.Context(), roleUUID, userUUID)
	if err != nil {
		if errors.Is(err, rolepkg.ErrRoleNotFound) {
			return &Response{
				Code: http.StatusNotFound,
				body: fmt.Sprintf("role not found: %v", err),
			}
		}
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to remove user from role: %v", err),
		}
	}

	return &Response{
		Code: http.StatusNoContent,
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
			ID   *string `json:"id,omitempty"`
			Name *string `json:"name,omitempty"`
		}{
			ID:   &uuidStr,
			Name: requestBody.Name,
		},
	}
}

// PutID handles updating an existing role
func (h *Handle) PutID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
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
		if errors.Is(err, rolepkg.ErrRoleNotFound) {
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

	return PutIDJSON200Response(struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}{
		Name: requestBody.Name,
		UUID: &uuidStr,
	})
}

// DeleteID handles deleting a role
func (h *Handle) DeleteID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	roleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	err = h.roleService.DeleteRole(r.Context(), roleUUID)
	if err != nil {
		if errors.Is(err, rolepkg.ErrRoleNotFound) {
			return &Response{
				Code: http.StatusNotFound,
				body: fmt.Sprintf("role not found: %v", err),
			}
		}
		if errors.Is(err, rolepkg.ErrRoleHasUsers) {
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
