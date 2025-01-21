package role

import (
	"net/http"
)

type Handle struct {
	roleService *RoleService
}

func NewHandle(roleService *RoleService) Handle {
	return Handle{
		roleService: roleService,
	}
}

// Get handles the GET / endpoint
func (h Handle) Get(w http.ResponseWriter, r *http.Request) *Response {
	roles, err := h.roleService.FindRoles(r.Context())
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to fetch roles",
		}
	}

	// Convert database rows to API response format
	apiRoles := make([]struct {
		Name *string `json:"name,omitempty"`
		UUID *string `json:"uuid,omitempty"`
	}, len(roles))
	
	for i, role := range roles {
		name := role.Name // Create a new variable to get the address
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
