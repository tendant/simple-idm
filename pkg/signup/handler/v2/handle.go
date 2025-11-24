package v2

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/loginflow"
	"github.com/tendant/simple-idm/pkg/signup"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

type Handle struct {
	signupService      *signup.SignupService
	loginFlowService   *loginflow.LoginFlowService
	tokenCookieService tg.TokenCookieService
}

func NewHandle(
	signupService *signup.SignupService,
	loginFlowService *loginflow.LoginFlowService,
	tokenCookieService tg.TokenCookieService,
) *Handle {
	return &Handle{
		signupService:      signupService,
		loginFlowService:   loginFlowService,
		tokenCookieService: tokenCookieService,
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

	// If auto-login is requested and password-based signup was used, log the user in
	if req.AutoLogin && req.Password != "" {
		// Perform auto-login using loginflow service
		ipAddress := getIPAddress(r)
		userAgent := r.UserAgent()
		fingerprintData := device.ExtractFingerprintDataFromRequest(r)
		fingerprintStr := device.GenerateFingerprint(fingerprintData)

		loginResult := h.loginFlowService.ProcessLogin(r.Context(), loginflow.Request{
			Username:             req.Email, // Use email as username
			Password:             req.Password,
			IPAddress:            ipAddress,
			UserAgent:            userAgent,
			DeviceFingerprint:    fingerprintData,
			DeviceFingerprintStr: fingerprintStr,
		})

		// If login failed, still return successful signup but without auto-login
		if loginResult.ErrorResponse != nil {
			slog.Warn("Auto-login failed after signup", "error", loginResult.ErrorResponse.Message)
			writeJSON(w, http.StatusCreated, SignupResponse{
				UserID:  result.LoginID,
				Message: "Registration successful, but auto-login failed. Please log in manually.",
			})
			return
		}

		// Set authentication cookies
		h.tokenCookieService.SetTokensCookie(w, loginResult.Tokens)

		// Return success response with user data
		if len(loginResult.Users) > 0 {
			user := loginResult.Users[0]
			writeJSON(w, http.StatusCreated, SignupResponse{
				UserID:  result.LoginID,
				Message: "Registration successful",
				Status:  "success",
				User: map[string]interface{}{
					"id":    user.UserId,
					"name":  user.DisplayName,
					"email": user.UserInfo.Email,
					"roles": user.Roles,
				},
			})
		} else {
			// Fallback if no user data is available
			writeJSON(w, http.StatusCreated, SignupResponse{
				UserID:  result.LoginID,
				Message: "Registration successful",
				Status:  "success",
			})
		}
		return
	}

	// Return standard success response (no auto-login)
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

// getIPAddress extracts the client IP address from the request
func getIPAddress(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
