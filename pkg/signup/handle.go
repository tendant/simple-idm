package signup

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/role"
)

type Handle struct {
	iamService          iam.IamService
	roleService         role.RoleService
	loginService        login.LoginService
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

func WithLoginService(ls login.LoginService) Option {
	return func(h *Handle) {
		h.loginService = ls
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
		// Check for specific error types
		var usernameErr logins.ErrUsernameAlreadyExists
		var passwordErr logins.ErrPasswordComplexity

		// Username already exists
		if errors.As(err, &usernameErr) {
			return &Response{
				Code: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": "Username already exists",
				},
				contentType: "application/json",
			}
		}

		// Password complexity error
		if errors.As(err, &passwordErr) {
			return &Response{
				Code: http.StatusBadRequest,
				body: map[string]interface{}{
					"error":   "Password does not meet complexity requirements",
					"details": passwordErr.Details,
				},
				contentType: "application/json",
			}
		}
		// All other errors
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

// GetPasswordPolicy returns the password complexity requirements
func (h Handle) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) *Response {
	policy := h.loginService.GetPasswordPolicy()
	return &Response{
		Code:        http.StatusOK,
		body:        policy,
		contentType: "application/json",
	}
}

// RegisterUserPasswordless handles user registration without password
// It creates a user with a random password and sets the passwordless flag
func (h Handle) RegisterUserPasswordless(w http.ResponseWriter, r *http.Request) *Response {
	if !h.registrationEnabled {
		return &Response{
			Code: http.StatusForbidden,
			body: "Registration is disabled",
		}
	}
	// Parse request body
	var request PasswordlessRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Please check your registration information and try again",
		}
	}

	// Validate required fields
	if request.Username == "" || request.Fullname == "" || request.Email == "" {
		slog.Error("Full name, username, and email are required")
		return &Response{
			Code: http.StatusBadRequest,
			body: "Full name, username, and email are required",
		}
	}

	// Determine role based on invitation code
	role := h.defaultRole
	if request.InvitationCode != "" {
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

	// Create the login without a password
	login, err := h.loginsService.CreateLoginWithoutPassword(r.Context(), request.Username, "")
	if err != nil {
		// Check for specific error types
		var usernameErr logins.ErrUsernameAlreadyExists

		// Username already exists
		if errors.As(err, &usernameErr) {
			return &Response{
				Code: http.StatusBadRequest,
				body: map[string]interface{}{
					"error": "Username already exists",
				},
				contentType: "application/json",
			}
		}

		// All other errors
		slog.Error("Failed to create login", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to register user",
		}
	}

	// Set flag indicating this is a passwordless account
	loginID, err := uuid.Parse(login.ID)
	if err != nil {
		slog.Error("Failed to parse login ID", "error", err)
	} else {
		err = h.loginService.GetRepository().SetPasswordlessFlag(r.Context(), loginID, true)
		if err != nil {
			slog.Error("Failed to set passwordless flag", "error", err)
			// Continue anyway, as the user is created
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
