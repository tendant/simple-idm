package role

import (
	"encoding/json"
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

	w.Header().Set("Location", roleUUID.String())
	
	// Return the created role information
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

// Put handles updating an existing role
func (h *Handle) Put(w http.ResponseWriter, r *http.Request) *Response {
	var requestBody PutJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("failed to decode request body: %v", err),
		}
	}

	if requestBody.UUID == nil || requestBody.Name == nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "uuid and name are required",
		}
	}

	roleUUID, err := uuid.Parse(*requestBody.UUID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: fmt.Sprintf("invalid UUID format: %v", err),
		}
	}

	err = h.roleService.UpdateRole(r.Context(), roleUUID, *requestBody.Name)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: fmt.Sprintf("failed to update role: %v", err),
		}
	}

	return &Response{
		Code: http.StatusOK,
	}
}
