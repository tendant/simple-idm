package v2

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm/pkg/signup"
)

type Handle struct {
	signupService *signup.SignupService
}

func NewHandle(signupService *signup.SignupService) *Handle {
	return &Handle{
		signupService: signupService,
	}
}

// RegisterRoutes registers all signup routes
func (h *Handle) RegisterRoutes(r chi.Router) {
	r.Post("/", h.Signup)
}

// Signup handles unified user registration (with or without password)
func (h *Handle) Signup(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode signup request", "error", err)
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate minimum required field
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "Email is required")
		return
	}

	var result *signup.RegisterUserResult
	var err error

	// Dynamically choose registration method based on whether password is provided
	if req.Password != "" {
		// Password-based registration
		result, err = h.signupService.RegisterUser(r.Context(), signup.RegisterUserRequest{
			Username:       req.Username,
			Password:       req.Password,
			Fullname:       req.Fullname,
			Email:          req.Email,
			InvitationCode: req.InvitationCode,
		})
	} else {
		// Passwordless registration
		result, err = h.signupService.RegisterUserPasswordless(r.Context(), signup.RegisterUserPasswordlessRequest{
			Username:       req.Username,
			Fullname:       req.Fullname,
			Email:          req.Email,
			InvitationCode: req.InvitationCode,
		})
	}

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return success response
	writeJSON(w, http.StatusCreated, SignupResponse{
		UserID:  result.LoginID,
		Message: "Registration successful",
	})
}

// handleServiceError converts service errors to HTTP responses
func (h *Handle) handleServiceError(w http.ResponseWriter, err error) {
	var signupErr *signup.SignupError
	if !errors.As(err, &signupErr) {
		// Generic error
		writeError(w, http.StatusInternalServerError, "An error occurred during registration")
		return
	}

	// Map error codes to HTTP status codes
	statusCode := http.StatusBadRequest
	switch signupErr.Code {
	case signup.ErrCodeRegistrationDisabled:
		statusCode = http.StatusForbidden
	case signup.ErrCodeInvalidRequest:
		statusCode = http.StatusBadRequest
	case signup.ErrCodeUsernameExists:
		statusCode = http.StatusConflict
	case signup.ErrCodeInternalError:
		statusCode = http.StatusInternalServerError
	case signup.ErrCodeRoleNotFound:
		statusCode = http.StatusNotFound
	default:
		statusCode = http.StatusBadRequest
	}

	// Build error response
	errorBody := map[string]interface{}{
		"error": signupErr.Message,
		"code":  signupErr.Code,
	}
	if signupErr.Details != nil {
		errorBody["details"] = signupErr.Details
	}

	writeJSON(w, statusCode, errorBody)
}

// Helper functions

func writeJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}
