package signup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/emailverification"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/role"
)

// SignupService handles user registration business logic
type SignupService struct {
	iamService               *iam.IamService
	roleService              *role.RoleService
	loginService             *login.LoginService
	loginsService            *logins.LoginsService
	emailVerificationService *emailverification.EmailVerificationService
	registrationEnabled      bool
	defaultRole              string
}

// SignupServiceOption is a functional option for configuring SignupService
type SignupServiceOption func(*SignupService)

// NewSignupService creates a new SignupService with the given options
func NewSignupService(opts ...SignupServiceOption) *SignupService {
	s := &SignupService{
		registrationEnabled: true, // Default to enabled
		defaultRole:         "user", // Default role
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// WithIamServiceForSignup sets the IAM service
func WithIamServiceForSignup(is *iam.IamService) SignupServiceOption {
	return func(s *SignupService) {
		s.iamService = is
	}
}

// WithRoleServiceForSignup sets the role service
func WithRoleServiceForSignup(rs *role.RoleService) SignupServiceOption {
	return func(s *SignupService) {
		s.roleService = rs
	}
}

// WithLoginServiceForSignup sets the login service
func WithLoginServiceForSignup(ls *login.LoginService) SignupServiceOption {
	return func(s *SignupService) {
		s.loginService = ls
	}
}

// WithLoginsServiceForSignup sets the logins service
func WithLoginsServiceForSignup(ls *logins.LoginsService) SignupServiceOption {
	return func(s *SignupService) {
		s.loginsService = ls
	}
}

// WithEmailVerificationServiceForSignup sets the email verification service
func WithEmailVerificationServiceForSignup(evs *emailverification.EmailVerificationService) SignupServiceOption {
	return func(s *SignupService) {
		s.emailVerificationService = evs
	}
}

// WithRegistrationEnabledForSignup sets whether registration is enabled
func WithRegistrationEnabledForSignup(enabled bool) SignupServiceOption {
	return func(s *SignupService) {
		s.registrationEnabled = enabled
	}
}

// WithDefaultRoleForSignup sets the default role for new users
func WithDefaultRoleForSignup(role string) SignupServiceOption {
	return func(s *SignupService) {
		s.defaultRole = role
	}
}

// RegisterUserRequest represents a user registration request
type RegisterUserRequest struct {
	Username       string
	Password       string
	Fullname       string
	Email          string
	InvitationCode string
}

// RegisterUserPasswordlessRequest represents a passwordless user registration request
type RegisterUserPasswordlessRequest struct {
	Username       string
	Fullname       string
	Email          string
	InvitationCode string
}

// RegisterUserResult represents the result of user registration
type RegisterUserResult struct {
	LoginID  string
	UserID   uuid.UUID
	Username string
	Email    string
}

// SignupError represents a signup-specific error
type SignupError struct {
	Code    string
	Message string
	Details interface{}
}

func (e *SignupError) Error() string {
	return e.Message
}

// Error codes
const (
	ErrCodeRegistrationDisabled   = "REGISTRATION_DISABLED"
	ErrCodeInvalidRequest         = "INVALID_REQUEST"
	ErrCodeInvalidInvitationCode  = "INVALID_INVITATION_CODE"
	ErrCodeRoleNotFound           = "ROLE_NOT_FOUND"
	ErrCodeUsernameExists         = "USERNAME_EXISTS"
	ErrCodePasswordComplexity     = "PASSWORD_COMPLEXITY"
	ErrCodeLoginCreationFailed    = "LOGIN_CREATION_FAILED"
	ErrCodeUserCreationFailed     = "USER_CREATION_FAILED"
	ErrCodeRoleAssignmentFailed   = "ROLE_ASSIGNMENT_FAILED"
	ErrCodeInternalError          = "INTERNAL_ERROR"
)

// IsRegistrationEnabled returns whether registration is enabled
func (s *SignupService) IsRegistrationEnabled() bool {
	return s.registrationEnabled
}

// IsEmailVerificationRequired returns whether email verification is required for signup
// When true, users must verify their email before being able to login
func (s *SignupService) IsEmailVerificationRequired() bool {
	return s.emailVerificationService != nil
}

// RegisterUser registers a new user with username and password
func (s *SignupService) RegisterUser(ctx context.Context, req RegisterUserRequest) (*RegisterUserResult, error) {
	if !s.registrationEnabled {
		return nil, &SignupError{
			Code:    ErrCodeRegistrationDisabled,
			Message: "Registration is disabled",
		}
	}

	// Validate required fields (only email and password for password-based registration)
	if req.Email == "" || req.Password == "" {
		return nil, &SignupError{
			Code:    ErrCodeInvalidRequest,
			Message: "Email and password are required",
		}
	}

	// Use email as username if not provided
	username := req.Username
	if username == "" {
		username = req.Email
		slog.Info("Username empty, using email as username", "email", req.Email)
	}

	// Use empty string for fullname if not provided
	fullname := req.Fullname

	// Determine role
	roleName := s.defaultRole
	if req.InvitationCode != "" {
		assignedRole, valid := GetRoleForInvitationCode(req.InvitationCode)
		if !valid {
			slog.Error("Invalid invitation code", "code", req.InvitationCode)
			return nil, &SignupError{
				Code:    ErrCodeInvalidInvitationCode,
				Message: "Invalid invitation code",
			}
		}
		roleName = assignedRole
		slog.Info("Role assigned via invitation code", "code", req.InvitationCode, "role", roleName)
	}

	// Get role ID
	roleID, err := s.roleService.GetRoleIdByName(ctx, roleName)
	if err != nil {
		slog.Error("Failed to get role ID", "role", roleName, "error", err)
		// Check if it's a "not found" error (404) vs database/system error (500)
		if errors.Is(err, role.ErrRoleNotFound) {
			return nil, &SignupError{
				Code:    ErrCodeRoleNotFound,
				Message: fmt.Sprintf("Role not found: %s", roleName),
			}
		}
		// Database or system error - return 500
		return nil, &SignupError{
			Code:    ErrCodeInternalError,
			Message: "Internal server error while processing registration",
		}
	}

	// Create login
	loginResult, err := s.loginsService.CreateLogin(ctx, logins.LoginCreateRequest{
		Username: username,
		Password: req.Password,
	}, "")
	if err != nil {
		return nil, s.handleLoginCreationError(err)
	}

	// Create user
	user, err := s.iamService.CreateUser(ctx, req.Email, username, fullname, []uuid.UUID{}, loginResult.ID)
	if err != nil {
		slog.Error("Failed to create user", "error", err)
		return nil, &SignupError{
			Code:    ErrCodeUserCreationFailed,
			Message: "Failed to create user",
		}
	}

	// Assign role
	err = s.roleService.AddUserToRole(ctx, roleID, user.ID, loginResult.Username)
	if err != nil {
		slog.Error("Failed to assign role", "error", err)
		return nil, &SignupError{
			Code:    ErrCodeRoleAssignmentFailed,
			Message: "Failed to assign role to user",
		}
	}

	// Send email verification (best effort)
	if s.emailVerificationService != nil {
		_, err = s.emailVerificationService.CreateVerificationToken(ctx, user.ID, fullname, req.Email)
		if err != nil {
			slog.Error("Failed to send verification email", "user_id", user.ID, "error", err)
			// Don't fail registration if email sending fails
		} else {
			slog.Info("Verification email sent", "user_id", user.ID, "email", req.Email)
		}
	}

	return &RegisterUserResult{
		LoginID:  loginResult.ID,
		UserID:   user.ID,
		Username: loginResult.Username,
		Email:    req.Email,
	}, nil
}

// RegisterUserPasswordless registers a new user without a password
func (s *SignupService) RegisterUserPasswordless(ctx context.Context, req RegisterUserPasswordlessRequest) (*RegisterUserResult, error) {
	if !s.registrationEnabled {
		return nil, &SignupError{
			Code:    ErrCodeRegistrationDisabled,
			Message: "Registration is disabled",
		}
	}

	// Validate required fields
	if req.Email == "" {
		return nil, &SignupError{
			Code:    ErrCodeInvalidRequest,
			Message: "Email is required",
		}
	}

	// Use email as username if not provided
	username := req.Username
	if username == "" {
		username = req.Email
		slog.Info("Username empty, using email as username", "email", req.Email)
	}

	// Use empty string for fullname if not provided
	fullname := req.Fullname

	// Determine role
	roleName := s.defaultRole
	if req.InvitationCode != "" {
		assignedRole, valid := GetRoleForInvitationCode(req.InvitationCode)
		if !valid {
			slog.Error("Invalid invitation code", "code", req.InvitationCode)
			return nil, &SignupError{
				Code:    ErrCodeInvalidInvitationCode,
				Message: "Invalid invitation code",
			}
		}
		roleName = assignedRole
		slog.Info("Role assigned via invitation code", "code", req.InvitationCode, "role", roleName)
	}

	// Get role ID
	roleID, err := s.roleService.GetRoleIdByName(ctx, roleName)
	if err != nil {
		slog.Error("Failed to get role ID", "role", roleName, "error", err)
		// Check if it's a "not found" error (404) vs database/system error (500)
		if errors.Is(err, role.ErrRoleNotFound) {
			return nil, &SignupError{
				Code:    ErrCodeRoleNotFound,
				Message: fmt.Sprintf("Role not found: %s", roleName),
			}
		}
		// Database or system error - return 500
		return nil, &SignupError{
			Code:    ErrCodeInternalError,
			Message: "Internal server error while processing registration",
		}
	}

	// Create login without password
	loginResult, err := s.loginsService.CreateLoginWithoutPassword(ctx, username, "")
	if err != nil {
		return nil, s.handleLoginCreationError(err)
	}

	// Set passwordless flag
	loginID, err := uuid.Parse(loginResult.ID)
	if err != nil {
		slog.Error("Failed to parse login ID", "error", err)
	} else {
		err = s.loginService.GetRepository().SetPasswordlessFlag(ctx, loginID, true)
		if err != nil {
			slog.Error("Failed to set passwordless flag", "error", err)
			// Continue anyway
		}
	}

	// Create user
	user, err := s.iamService.CreateUser(ctx, req.Email, username, fullname, []uuid.UUID{}, loginResult.ID)
	if err != nil {
		slog.Error("Failed to create user", "error", err)
		return nil, &SignupError{
			Code:    ErrCodeUserCreationFailed,
			Message: "Failed to create user",
		}
	}

	// Assign role
	err = s.roleService.AddUserToRole(ctx, roleID, user.ID, loginResult.Username)
	if err != nil {
		slog.Error("Failed to assign role", "error", err)
		return nil, &SignupError{
			Code:    ErrCodeRoleAssignmentFailed,
			Message: "Failed to assign role to user",
		}
	}

	// Send email verification (best effort)
	if s.emailVerificationService != nil {
		_, err = s.emailVerificationService.CreateVerificationToken(ctx, user.ID, fullname, req.Email)
		if err != nil {
			slog.Error("Failed to send verification email", "user_id", user.ID, "error", err)
			// Don't fail registration if email sending fails
		} else {
			slog.Info("Verification email sent", "user_id", user.ID, "email", req.Email)
		}
	}

	return &RegisterUserResult{
		LoginID:  loginResult.ID,
		UserID:   user.ID,
		Username: username,
		Email:    req.Email,
	}, nil
}

// GetPasswordPolicy returns the password complexity requirements
func (s *SignupService) GetPasswordPolicy() *login.PasswordPolicy {
	return s.loginService.GetPasswordPolicy()
}

// handleLoginCreationError converts login creation errors to signup errors
func (s *SignupService) handleLoginCreationError(err error) error {
	var usernameErr logins.ErrUsernameAlreadyExists
	var passwordErr logins.ErrPasswordComplexity

	if errors.As(err, &usernameErr) {
		return &SignupError{
			Code:    ErrCodeUsernameExists,
			Message: "Username already exists",
		}
	}

	if errors.As(err, &passwordErr) {
		return &SignupError{
			Code:    ErrCodePasswordComplexity,
			Message: "Password does not meet complexity requirements",
			Details: passwordErr.Details,
		}
	}

	slog.Error("Failed to create login", "error", err)
	return &SignupError{
		Code:    ErrCodeLoginCreationFailed,
		Message: "Failed to create login",
	}
}
