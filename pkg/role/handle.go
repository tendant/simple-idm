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

type Response struct {
	Code int
	body interface{}
}

// GetRoles handles the GET /roles endpoint
func (h Handle) GetRoles(w http.ResponseWriter, r *http.Request) *Response {
	roles, err := h.roleService.FindRoles(r.Context())
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to fetch roles",
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: roles,
	}
}
