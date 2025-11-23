package v2

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/loginflow"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Handle contains dependencies for HTTP handlers
type Handle struct {
	loginService       *login.LoginService
	loginFlowService   *loginflow.LoginFlowService
	tokenCookieService tg.TokenCookieService
}

// NewHandle creates a new v2 login handler
func NewHandle(
	loginService *login.LoginService,
	loginFlowService *loginflow.LoginFlowService,
	tokenCookieService tg.TokenCookieService,
) *Handle {
	return &Handle{
		loginService:       loginService,
		loginFlowService:   loginFlowService,
		tokenCookieService: tokenCookieService,
	}
}

// RegisterRoutes registers all login routes
func (h *Handle) RegisterRoutes(r chi.Router) {
	r.Post("/login", h.Login)
	r.Post("/logout", h.Logout)
	r.Post("/magic-link", h.RequestMagicLink)
	r.Get("/magic-link/validate", h.ValidateMagicLink)
	r.Post("/password/reset/init", h.InitPasswordReset)
	r.Post("/password/reset", h.CompletePasswordReset)
	r.Post("/token/refresh", h.RefreshToken)
}

// Login handles POST /api/v2/idm/login
func (h *Handle) Login(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract request metadata
	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Call loginflow service
	result := h.loginFlowService.ProcessLogin(r.Context(), loginflow.Request{
		Username:             req.Username,
		Password:             req.Password,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	})

	// Handle errors
	if result.ErrorResponse != nil {
		h.writeLoginError(w, result.ErrorResponse)
		return
	}

	// Set cookies for all scenarios
	h.tokenCookieService.SetTokensCookie(w, result.Tokens)

	// Handle 2FA required
	if result.RequiresTwoFA {
		h.write2FARequiredResponse(w, result)
		return
	}

	// Handle user selection required
	if result.RequiresUserSelection {
		h.writeUserSelectionResponse(w, result)
		return
	}

	// Success - return user data
	h.writeSuccessResponse(w, result)
}

// Logout handles POST /api/v2/idm/login/logout
func (h *Handle) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear cookies
	h.tokenCookieService.ClearCookies(w)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "logged out successfully",
		"success": true,
	})
}

// RequestMagicLink handles POST /api/v2/idm/login/magic-link
func (h *Handle) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	var req MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// TODO: Implement magic link logic
	writeJSON(w, http.StatusOK, MagicLinkResponse{
		Message: "Magic link sent to your email",
		Success: true,
	})
}

// ValidateMagicLink handles GET /api/v2/idm/login/magic-link/validate
func (h *Handle) ValidateMagicLink(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	// TODO: Implement magic link validation
	writeJSON(w, http.StatusOK, MagicLinkValidateResponse{
		Status:  "success",
		Message: "Magic link validated",
	})
}

// InitPasswordReset handles POST /api/v2/idm/login/password/reset/init
func (h *Handle) InitPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// TODO: Implement password reset initiation
	writeJSON(w, http.StatusOK, PasswordResetInitResponse{
		Message: "Password reset instructions sent",
		Success: true,
	})
}

// CompletePasswordReset handles POST /api/v2/idm/login/password/reset
func (h *Handle) CompletePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// TODO: Implement password reset completion
	writeJSON(w, http.StatusOK, PasswordResetResponse{
		Message: "Password reset successfully",
		Success: true,
	})
}

// RefreshToken handles POST /api/v2/idm/login/token/refresh
func (h *Handle) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement token refresh
	writeJSON(w, http.StatusOK, RefreshTokenResponse{
		Message: "Token refreshed",
		Success: true,
	})
}

// Helper methods for response formatting

func (h *Handle) writeLoginError(w http.ResponseWriter, err *loginflow.Error) {
	statusCode := http.StatusBadRequest
	if err.Type == "ACCOUNT_LOCKED" {
		statusCode = http.StatusForbidden
	}

	writeJSON(w, statusCode, map[string]interface{}{
		"error": err.Message,
		"code":  err.Type,
	})
}

func (h *Handle) write2FARequiredResponse(w http.ResponseWriter, result loginflow.Result) {
	methods := make([]TwoFactorMethodInfo, len(result.TwoFactorMethods))
	for i, m := range result.TwoFactorMethods {
		// Convert []DeliveryOption to []string
		deliveryOptions := make([]string, len(m.DeliveryOptions))
		for j, opt := range m.DeliveryOptions {
			deliveryOptions[j] = opt.DisplayValue
		}

		methods[i] = TwoFactorMethodInfo{
			Type:            m.Type,
			DeliveryOptions: deliveryOptions,
			DisplayName:     m.Type, // Use type as display name since DisplayName field doesn't exist
		}
	}

	tempToken := ""
	if result.Tokens != nil {
		if token, ok := result.Tokens[tg.TEMP_TOKEN_NAME]; ok {
			tempToken = token.Token
		}
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		Status:           "2fa_required",
		TempToken:        tempToken,
		TwoFactorMethods: methods,
		Message:          "Two-factor authentication required",
	})
}

func (h *Handle) writeUserSelectionResponse(w http.ResponseWriter, result loginflow.Result) {
	users := make([]interface{}, len(result.Users))
	for i, u := range result.Users {
		users[i] = map[string]interface{}{
			"id":    u.UserId,
			"name":  u.DisplayName,
			"email": u.UserInfo.Email,
			"roles": u.Roles,
		}
	}

	tempToken := ""
	if result.Tokens != nil {
		if token, ok := result.Tokens[tg.TEMP_TOKEN_NAME]; ok {
			tempToken = token.Token
		}
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		Status:    "user_selection_required",
		Users:     users,
		TempToken: tempToken,
		Message:   "Please select a user account",
	})
}

func (h *Handle) writeSuccessResponse(w http.ResponseWriter, result loginflow.Result) {
	if len(result.Users) == 0 {
		slog.Error("Login successful but no users found")
		writeError(w, http.StatusInternalServerError, "unexpected error")
		return
	}

	user := result.Users[0]
	writeJSON(w, http.StatusOK, LoginResponse{
		Status: "success",
		User: map[string]interface{}{
			"id":    user.UserId,
			"name":  user.DisplayName,
			"email": user.UserInfo.Email,
			"roles": user.Roles,
		},
		Message: "login successful",
	})
}
