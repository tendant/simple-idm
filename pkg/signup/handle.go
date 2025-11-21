package signup

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm/pkg/emailverification"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/role"
)

// Handle handles HTTP requests for signup operations
type Handle struct {
	service *SignupService
}

type Option func(*Handle)

// NewHandle creates a new HTTP handler with the given signup service
func NewHandle(service *SignupService) *Handle {
	return &Handle{
		service: service,
	}
}

// NewHandleWithOptions creates a new HTTP handler with legacy options pattern
// Deprecated: Use NewHandle with NewSignupService instead
func NewHandleWithOptions(opts ...Option) *Handle {
	// Temporary handle to collect options
	tempHandle := &Handle{}
	for _, opt := range opts {
		opt(tempHandle)
	}

	// If service was set directly via options, use it
	if tempHandle.service != nil {
		return tempHandle
	}

	// Otherwise create a default service
	tempHandle.service = NewSignupService()
	return tempHandle
}

// WithSignupService sets the signup service directly
func WithSignupService(s *SignupService) Option {
	return func(h *Handle) {
		h.service = s
	}
}

// Legacy options for backward compatibility
// Deprecated: Use NewSignupService with service options instead

func WithIamService(is iam.IamService) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.iamService = &is
	}
}

func WithRoleService(rs role.RoleService) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.roleService = &rs
	}
}

func WithLoginsService(ls logins.LoginsService) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.loginsService = &ls
	}
}

func WithLoginService(ls login.LoginService) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.loginService = &ls
	}
}

func WithRegistrationEnabled(enabled bool) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.registrationEnabled = enabled
	}
}

func WithDefaultRole(role string) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.defaultRole = role
	}
}

func WithEmailVerificationService(evs *emailverification.EmailVerificationService) Option {
	return func(h *Handle) {
		if h.service == nil {
			h.service = NewSignupService()
		}
		h.service.emailVerificationService = evs
	}
}

// RegisterUser handles user registration with optional invitation code
func (h Handle) RegisterUser(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	var request RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Please check your registration information and try again",
		}
	}

	// Call service
	result, err := h.service.RegisterUser(r.Context(), RegisterUserRequest{
		Username:       request.Username,
		Password:       request.Password,
		Fullname:       request.Fullname,
		Email:          request.Email,
		InvitationCode: request.InvitationCode,
	})

	if err != nil {
		return h.handleServiceError(err)
	}

	// Return success response
	return &Response{
		Code: http.StatusCreated,
		body: map[string]interface{}{
			"id":       result.LoginID,
			"username": result.Username,
		},
		contentType: "application/json",
	}
}

// GetPasswordPolicy returns the password complexity requirements
func (h Handle) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) *Response {
	policy := h.service.GetPasswordPolicy()
	return &Response{
		Code:        http.StatusOK,
		body:        policy,
		contentType: "application/json",
	}
}

// RegisterUserPasswordless handles user registration without password
func (h Handle) RegisterUserPasswordless(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	var request PasswordlessRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Please check your registration information and try again",
		}
	}

	// Call service
	result, err := h.service.RegisterUserPasswordless(r.Context(), RegisterUserPasswordlessRequest{
		Username:       request.Username,
		Fullname:       request.Fullname,
		Email:          request.Email,
		InvitationCode: request.InvitationCode,
	})

	if err != nil {
		return h.handleServiceError(err)
	}

	// Return success response
	return &Response{
		Code: http.StatusCreated,
		body: map[string]interface{}{
			"id":       result.LoginID,
			"username": result.Username,
		},
		contentType: "application/json",
	}
}

// handleServiceError converts service errors to HTTP responses
func (h Handle) handleServiceError(err error) *Response {
	var signupErr *SignupError
	if !errors.As(err, &signupErr) {
		// Generic error
		return &Response{
			Code: http.StatusInternalServerError,
			body: "An error occurred during registration",
		}
	}

	// Map error codes to HTTP status codes
	statusCode := http.StatusBadRequest
	switch signupErr.Code {
	case ErrCodeRegistrationDisabled:
		statusCode = http.StatusForbidden
	case ErrCodeInvalidRequest:
		statusCode = http.StatusBadRequest
	case ErrCodeUsernameExists:
		statusCode = http.StatusConflict
	case ErrCodeInternalError:
		statusCode = http.StatusInternalServerError
	case ErrCodeRoleNotFound:
		statusCode = http.StatusNotFound
	default:
		statusCode = http.StatusBadRequest
	}

	// Build error response
	body := map[string]interface{}{
		"error": signupErr.Message,
		"code":  signupErr.Code,
	}
	if signupErr.Details != nil {
		body["details"] = signupErr.Details
	}

	return &Response{
		Code:        statusCode,
		body:        body,
		contentType: "application/json",
	}
}
