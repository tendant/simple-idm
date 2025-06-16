package signup

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/role"
)

type Handle struct {
	iamService          iam.IamService
	roleService         role.RoleService
	loginsService       logins.LoginsService
	registrationEnabled bool
	defaultRole         string
}

type Option func(*Handle)

func NewHandle(opts ...Option) *Handle {
	h := &Handle{}

	// Apply all options
	for _, opt := range opts {
		opt(h)
	}

	return h
}

func WithIamService(is iam.IamService) Option {
	return func(h *Handle) {
		h.iamService = is
	}
}

func WithRoleService(rs role.RoleService) Option {
	return func(h *Handle) {
		h.roleService = rs
	}
}

func WithLoginsService(ls logins.LoginsService) Option {
	return func(h *Handle) {
		h.loginsService = ls
	}
}

func WithRegistrationEnabled(enabled bool) Option {
	return func(h *Handle) {
		h.registrationEnabled = enabled
	}
}

func WithDefaultRole(role string) Option {
	return func(h *Handle) {
		h.defaultRole = role
	}
}

// RegisterUser handles user registration with optional invitation code
// 2025-06-10: Designed for sales demo instance to allow user to register with optional invitation code
func (h Handle) RegisterUser(w http.ResponseWriter, r *http.Request) *Response {
	if !h.registrationEnabled {
		return &Response{
			Code: http.StatusForbidden,
			body: "Registration is disabled",
		}
	}
	// Parse request body
	var request RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Please check your registration information and try again",
		}
	}

	// Validate required fields
	if request.Username == "" || request.Password == "" || request.Fullname == "" || request.Email == "" {
		slog.Error("Full name, username, password, and email are required")
		return &Response{
			Code: http.StatusBadRequest,
			body: "Full name, username, password, and email are required",
		}
	}

	// Determine role based on invitation code
	role := h.defaultRole
	if request.InvitationCode != "" {
		// Get role from invitation code
		assignedRole, valid := GetRoleForInvitationCode(request.InvitationCode)
		if !valid {
			slog.Error("Unrecognized invitation code", "code", request.InvitationCode)
			return &Response{
				Code: http.StatusBadRequest,
				body: "Invalid invitation code",
			}
		}
		role = assignedRole
		slog.Info("Role assigned based on invitation code", "code", request.InvitationCode, "role", role)
	}

	// Get role ID
	roleID, err := h.roleService.GetRoleIdByName(r.Context(), role)
	if err != nil {
		slog.Error("Failed to get role ID", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to register user",
		}
	}
	slog.Info("Role ID", "role_id", roleID)

	// Create the login
	login, err := h.loginsService.CreateLogin(r.Context(), logins.LoginCreateRequest{
		Username: request.Username,
		Password: request.Password,
	}, "")
	if err != nil {
		slog.Error("Failed to create login", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to register user",
		}
	}

	// Create user
	user, err := h.iamService.CreateUser(r.Context(), request.Email, request.Username, request.Fullname, []uuid.UUID{}, login.ID)
	if err != nil {
		slog.Error("Failed to create user", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to register user",
		}
	}

	// Add user to role
	err = h.roleService.AddUserToRole(r.Context(), roleID, user.ID, login.Username)
	if err != nil {
		slog.Error("Failed to add user to role", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to register user",
		}
	}

	// Return the created login
	return &Response{
		Code:        http.StatusCreated,
		body:        login,
		contentType: "application/json",
	}
}
