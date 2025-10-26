package loginapi

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/loginflow"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

type Handle struct {
	loginService       *login.LoginService
	loginFlowService   *loginflow.LoginFlowService
	tokenCookieService tg.TokenCookieService
	responseHandler    ResponseHandler
}

type Option func(*Handle)

func NewHandle(opts ...Option) Handle {
	h := Handle{
		responseHandler: NewDefaultResponseHandler(),
	}
	for _, opt := range opts {
		opt(&h)
	}
	return h
}

func WithLoginService(ls *login.LoginService) Option {
	return func(h *Handle) {
		h.loginService = ls
	}
}

func WithLoginFlowService(lfs *loginflow.LoginFlowService) Option {
	return func(h *Handle) {
		h.loginFlowService = lfs
	}
}

func WithTokenCookieService(tcs tg.TokenCookieService) Option {
	return func(h *Handle) {
		h.tokenCookieService = tcs
	}
}

func WithResponseHandler(rh ResponseHandler) Option {
	return func(h *Handle) {
		h.responseHandler = rh
	}
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// Login a user
// (POST /login)
func (h Handle) PostLogin(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := PostLoginJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Log username and hashed password
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte(data.Password)))
	slog.Info("Login request", "username", data.Username, "password_hash", passwordHash)

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the login
	loginRequest := loginflow.Request{
		Username:             data.Username,
		Password:             data.Password,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	}

	result := h.loginFlowService.ProcessLogin(r.Context(), loginRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle 2FA required
	if result.RequiresTwoFA {
		h.tokenCookieService.SetTokensCookie(w, result.Tokens)
		return h.prepare2FARequiredResponse(w, result.TwoFactorMethods, result.Tokens)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		h.tokenCookieService.SetTokensCookie(w, result.Tokens)
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Convert mapped users to API users
	apiUsers := make([]User, len(result.Users))
	for i, mu := range result.Users {
		email := mu.UserInfo.Email
		name := mu.DisplayName

		// Use the Roles field directly - it's always populated and safe
		roles := mu.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
		}
	}

	h.tokenCookieService.SetTokensCookie(w, result.Tokens)

	// Safety check: ensure we have at least one user
	if len(apiUsers) == 0 {
		slog.Error("Login successful but no users found in result",
			"loginID", result.LoginID,
			"tokens_present", len(result.Tokens) > 0)
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{
				"error": "Login succeeded but user data not found",
			},
		}
	}

	// Create response with user information
	response := Login{
		Status:  STATUS_SUCCESS,
		Message: "Login successful",
		User:    apiUsers[0],
		Users:   apiUsers,
	}

	return PostLoginJSON200Response(response)
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// LoginByEmail handles email-based login
// (POST /login/email)
func (h Handle) LoginByEmail(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := LoginByEmailJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Log email and hashed password
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte(data.Password)))
	slog.Info("Email login request", "email", data.Email, "password_hash", passwordHash)

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)

	// Use loginflow service to process the email login
	result := h.loginFlowService.ProcessLoginByEmail(r.Context(), string(data.Email), data.Password, ipAddress, userAgent, fingerprintData)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle 2FA required
	if result.RequiresTwoFA {
		h.tokenCookieService.SetTokensCookie(w, result.Tokens)
		return h.prepare2FARequiredResponse(w, result.TwoFactorMethods, result.Tokens)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		h.tokenCookieService.SetTokensCookie(w, result.Tokens)
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Convert mapped users to API users
	apiUsers := make([]User, len(result.Users))
	for i, mu := range result.Users {
		email := mu.UserInfo.Email
		name := mu.DisplayName

		// Use the Roles field directly - it's always populated and safe
		roles := mu.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
		}
	}

	// Create response with user information
	response := Login{
		Status:  STATUS_SUCCESS,
		Message: "Login successful",
		User:    apiUsers[0],
		Users:   apiUsers,
	}

	return LoginByEmailJSON200Response(response)
}

// 2025-08-11: Added a set of functions to handle login by email
// InitiateMagicLinkLoginByEmail handles requests for magic link login using email
// (POST /login/magic-link/email)
func (h Handle) InitiateMagicLinkLoginByEmail(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	var request MagicLinkEmailLoginRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Generate magic link token using email
	token, email, err := h.loginService.GenerateMagicLinkTokenByEmail(r.Context(), string(request.Email))
	if err != nil {
		// Return success even if user not found to prevent email enumeration
		return &Response{
			Code: http.StatusOK,
			body: map[string]string{
				"message": "If an account exists with that email, we will send a login link to it.",
			},
			contentType: "application/json",
		}
	}

	// Send magic link email
	err = h.loginService.SendMagicLinkEmail(r.Context(), login.SendMagicLinkEmailParams{
		Email:    email,
		Token:    token,
		Username: string(request.Email), // Use email as username for the email template
	})
	if err != nil {
		slog.Error("Failed to send magic link email", "error", err)
		// Return success anyway to prevent email enumeration
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{
			"message": "If an account exists with that email, we will send a login link to it.",
		},
		contentType: "application/json",
	}
}

// 2025-08-11: Added a set of functions to handle login by email
// InitiatePasswordResetByEmail handles password reset requests using email
// (POST /password/reset/init/email)
func (h Handle) InitiatePasswordResetByEmail(w http.ResponseWriter, r *http.Request) *Response {
	var body InitiatePasswordResetByEmailJSONRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		slog.Error("Failed extracting email", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed extracting email",
		}
	}

	if body.Email == "" {
		return &Response{
			body: map[string]string{
				"message": "Email is required",
			},
			Code:        400,
			contentType: "application/json",
		}
	}

	err = h.loginService.InitPasswordResetByEmail(r.Context(), string(body.Email))
	if err != nil {
		// Log the error but return 200 to prevent email enumeration
		slog.Error("Failed to init password reset for email", "err", err, "email", body.Email)
	}

	return &Response{
		body: map[string]string{
			"message": "If an account exists with that email, we will send password reset instructions to it.",
		},
		Code:        http.StatusOK,
		contentType: "application/json",
	}
}

func (h Handle) PostPasswordResetInit(w http.ResponseWriter, r *http.Request) *Response {
	var body PostPasswordResetInitJSONBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		slog.Error("Failed extracting username", "err", err)
		http.Error(w, "Failed extracting username", http.StatusBadRequest)
		return nil
	}

	if body.Username == "" {
		return &Response{
			body: map[string]string{
				"message": "Username is required",
			},
			Code:        400,
			contentType: "application/json",
		}
	}

	err = h.loginService.InitPasswordReset(r.Context(), body.Username)
	if err != nil {
		// Log the error but return 200 to prevent username enumeration
		slog.Error("Failed to init password reset for username", "err", err, "username", body.Username)
	}

	return &Response{
		body: map[string]string{
			"message": "If an account exists with that username, we will send a password reset link to the associated email.",
		},
		Code:        http.StatusOK,
		contentType: "application/json",
	}
}

func (h Handle) PostPasswordReset(w http.ResponseWriter, r *http.Request) *Response {
	var body PostPasswordResetJSONBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		slog.Error("Failed extracting password reset data", "err", err)
		http.Error(w, "Failed extracting password reset data", http.StatusBadRequest)
		return nil
	}

	if body.Token == "" || body.NewPassword == "" {
		return &Response{
			body: map[string]string{
				"message": "Token and new password are required",
			},
			Code:        400,
			contentType: "application/json",
		}
	}

	err = h.loginService.ResetPassword(r.Context(), body.Token, body.NewPassword)
	if err != nil {
		slog.Error("Failed to reset password", "err", err)
		return &Response{
			body: map[string]string{
				"message": err.Error(),
			},
			Code:        400,
			contentType: "application/json",
		}
	}

	return &Response{
		body: map[string]string{
			"message": "Password has been reset successfully",
		},
		Code:        200,
		contentType: "application/json",
	}
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// PostTokenRefresh handles the token refresh endpoint
// (POST /token/refresh)
func (h Handle) PostTokenRefresh(w http.ResponseWriter, r *http.Request) *Response {
	// Get refresh token from cookie
	cookie, err := r.Cookie(tg.REFRESH_TOKEN_NAME)
	if err != nil {
		slog.Error("No Refresh Token Cookie", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "No refresh token cookie",
		}
	}

	// Use loginflow service to process the token refresh
	refreshRequest := loginflow.TokenRefreshRequest{
		RefreshToken: cookie.Value,
	}

	result := h.loginFlowService.ProcessTokenRefresh(r.Context(), refreshRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Set tokens in cookies for web flow
	err = h.tokenCookieService.SetTokensCookie(w, result.Tokens)
	if err != nil {
		slog.Error("Failed to set tokens cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens cookie",
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: "",
	}
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// PostMobileTokenRefresh handles the mobile token refresh endpoint
// (POST /mobile/token/refresh)
func (h Handle) PostMobileTokenRefresh(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	var data PostMobileTokenRefreshJSONBody
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		slog.Error("Unable to parse request body", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Validate refresh token is provided
	if data.RefreshToken == "" {
		slog.Error("No refresh token provided in request body")
		return &Response{
			Code: http.StatusBadRequest,
			body: "Refresh token is required",
		}
	}

	// Use loginflow service to process the mobile token refresh
	refreshRequest := loginflow.TokenRefreshRequest{
		RefreshToken: data.RefreshToken,
	}

	result := h.loginFlowService.ProcessMobileTokenRefresh(r.Context(), refreshRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(result.Tokens)
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// Switch to a different user when multiple users are available for the same login
// (POST /user/switch)
func (h Handle) PostUserSwitch(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := PostUserSwitchJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Get token from cookie instead of Authorization header
	cookie, err := r.Cookie(tg.TEMP_TOKEN_NAME)
	if err != nil {
		slog.Error("No Temp Token Cookie", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Missing temp token cookie",
		}
	}
	tokenStr := cookie.Value

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the user switch
	switchRequest := loginflow.UserSwitchRequest{
		TokenString:          tokenStr,
		TokenType:            "temp_token",
		TargetUserID:         data.UserID,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	}

	result := h.loginFlowService.ProcessUserSwitch(r.Context(), switchRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Set tokens in cookies for web flow
	err = h.tokenCookieService.SetTokensCookie(w, result.Tokens)
	if err != nil {
		slog.Error("Failed to set tokens in cookies", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens in cookies",
		}
	}

	// Convert mapped users to API users (including all available users)
	return h.responseHandler.PrepareUserSwitchResponse(result.Users)
}

// 2025-08-25: refactor Mobile Login routes to move business logic into service layer
func (h Handle) PostMobileLogin(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := PostLoginJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the mobile login
	loginRequest := loginflow.Request{
		Username:             data.Username,
		Password:             data.Password,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	}

	result := h.loginFlowService.ProcessMobileLogin(r.Context(), loginRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle 2FA required
	if result.RequiresTwoFA {
		return h.prepare2FARequiredResponse(w, result.TwoFactorMethods, result.Tokens)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(result.Tokens)
}

func (h Handle) PostLogout(w http.ResponseWriter, r *http.Request) *Response {
	// Use loginflow service to process the logout
	result := h.loginFlowService.ProcessLogout(r.Context())

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Set logout token cookie
	err := h.tokenCookieService.SetTokensCookie(w, result.Tokens)
	if err != nil {
		slog.Error("Failed to set logout token cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set logout token cookie",
		}
	}

	// Clear cookies
	err = h.tokenCookieService.ClearCookies(w)
	if err != nil {
		slog.Error("Failed to clear cookies", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to clear cookies",
		}
	}

	return &Response{
		Code: http.StatusOK,
	}
}

func (h Handle) PostUsernameFind(w http.ResponseWriter, r *http.Request) *Response {
	var body PostUsernameFindJSONRequestBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		slog.Error("Failed extracting email", "err", err)
		http.Error(w, "Failed extracting email", http.StatusBadRequest)
		return nil
	}

	if body.Email != "" {
		username, valid, err := h.loginService.FindUsernameByEmail(r.Context(), string(body.Email))
		if err != nil || !valid {
			// Return 200 even if user not found to prevent email enumeration
			slog.Info("Username not found for email", "email", body.Email)
			return &Response{
				body: map[string]string{
					"message": "If an account exists with that email, we will send the username to it.",
				},
				Code:        200,
				contentType: "application/json",
			}
		}

		// TODO: Send email with username
		err = h.loginService.SendUsernameEmail(r.Context(), string(body.Email), username)
		if err != nil {
			slog.Error("Failed to send username email", "err", err, "email", body.Email)
			// Still return 200 to prevent email enumeration
			return &Response{
				body: map[string]string{
					"message": "If an account exists with that email, we will send the username to it.",
				},
				Code:        200,
				contentType: "application/json",
			}
		}

		return &Response{
			body: map[string]string{
				"message": "If an account exists with that email, we will send the username to it.",
			},
			Code:        200,
			contentType: "application/json",
		}
	}

	slog.Error("Email is missing in the request body")
	http.Error(w, "Email is required", http.StatusBadRequest)
	return nil
}

// Initiate sending 2fa code
// (POST /2fa/send)
func (h Handle) Post2faSend(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	data := &Post2faSendJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Get token from cookie instead of Authorization header
	cookie, err := r.Cookie(tg.TEMP_TOKEN_NAME)
	if err != nil {
		slog.Error("No Temp Token Cookie", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Missing temp token cookie",
		}
	}
	tokenStr := cookie.Value

	slog.Info("found temp token")

	// Use loginflow service to process the 2FA send
	sendRequest := loginflow.TwoFASendRequest{
		TokenString:    tokenStr,
		UserID:         data.UserID,
		TwoFAType:      data.TwofaType,
		DeliveryOption: data.DeliveryOption,
	}

	result := h.loginFlowService.Process2FASend(r.Context(), sendRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	resp.Result = "success"
	return Post2faSendJSON200Response(resp)
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// Authenticate 2fa passcode
// (POST /2fa/validate)
func (h Handle) Post2faValidate(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	// Get token from cookie instead of Authorization header
	cookie, err := r.Cookie(tg.TEMP_TOKEN_NAME)
	if err != nil {
		slog.Error("No Temp Token Cookie", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Missing temp token cookie",
		}
	}
	tokenStr := cookie.Value

	// Parse request body
	data := &Post2faValidateJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the 2FA validation
	validationRequest := loginflow.TwoFAValidationRequest{
		TokenString:          tokenStr,
		TwoFAType:            data.TwofaType,
		Passcode:             data.Passcode,
		RememberDevice:       data.RememberDevice2fa,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	}

	result := h.loginFlowService.Process2FAValidation(r.Context(), validationRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle user association flow (now handled by loginflow service)
	if result.RequiresUserAssociation {
		return h.prepareUserAssociationSelectionResponse(w, result.LoginID.String(), result.UserAssociationUserID, result.Users)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection && len(result.Users) > 0 {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Set tokens in cookies for web flow
	err = h.tokenCookieService.SetTokensCookie(w, result.Tokens)
	if err != nil {
		slog.Error("Failed to set tokens cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens cookie",
		}
	}

	// Include tokens in response
	resp.Result = "success"

	return Post2faValidateJSON200Response(resp)
}

// GetPasswordResetPolicy returns the current password policy
func (h Handle) GetPasswordResetPolicy(w http.ResponseWriter, r *http.Request, params GetPasswordResetPolicyParams) *Response {
	// validate token before returning policy
	_, err := h.loginService.GetPasswordManager().ValidateResetToken(r.Context(), params.Token)
	if err != nil {
		return &Response{
			body: "Invalid or expired reset token",
			Code: http.StatusBadRequest,
		}
	}

	// get policy and respond
	policy := h.loginService.GetPasswordPolicy()

	// Map the policy fields to the response fields using snake_case
	response := PasswordPolicyResponse{
		MinLength:          &policy.MinLength,
		RequireUppercase:   &policy.RequireUppercase,
		RequireLowercase:   &policy.RequireLowercase,
		RequireDigit:       &policy.RequireDigit,
		RequireSpecialChar: &policy.RequireSpecialChar,
		DisallowCommonPwds: &policy.DisallowCommonPwds,
		MaxRepeatedChars:   &policy.MaxRepeatedChars,
		HistoryCheckCount:  &policy.HistoryCheckCount,
	}

	// Convert the duration to days and assign it to the response
	expirationDays := int(policy.GetExpirationPeriod().Hours() / 24)
	response.ExpirationDays = &expirationDays

	return GetPasswordResetPolicyJSON200Response(response)
}

func (h Handle) PostMobile2faSend(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	data := &PostMobile2faSendJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Get token from request body
	if data.TempToken == "" {
		slog.Error("No temp token in request body")
		return &Response{
			Code: http.StatusBadRequest,
			body: "Missing temp token in request body",
		}
	}
	tokenStr := data.TempToken

	// Use loginflow service to process the 2FA send
	sendRequest := loginflow.TwoFASendRequest{
		TokenString:    tokenStr,
		UserID:         data.UserID,
		TwoFAType:      data.TwofaType,
		DeliveryOption: data.DeliveryOption,
	}

	result := h.loginFlowService.Process2FASend(r.Context(), sendRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	resp.Result = "success"
	return Post2faSendJSON200Response(resp)
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// (POST /mobile/2fa/validate)
func (h Handle) PostMobile2faValidate(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := &PostMobile2faValidateJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Get token from request body
	if data.TempToken == "" {
		slog.Error("No temp token in request body")
		return &Response{
			Code: http.StatusBadRequest,
			body: "Missing temp token in request body",
		}
	}
	tokenStr := data.TempToken

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the mobile 2FA validation
	validationRequest := loginflow.TwoFAValidationRequest{
		TokenString:          tokenStr,
		TwoFAType:            data.TwofaType,
		Passcode:             data.Passcode,
		RememberDevice:       data.RememberDevice2fa,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	}

	result := h.loginFlowService.ProcessMobile2FAValidation(r.Context(), validationRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(result.Tokens)
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// (POST /mobile/user/switch)
func (h Handle) PostMobileUserSwitch(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := PostMobileUserSwitchJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Get token from either request body or Authorization header
	var tokenStr string
	var tokenType string

	// Check if token is in the request body
	if data.TempToken != nil && *data.TempToken != "" {
		tokenStr = *data.TempToken
		tokenType = tg.TEMP_TOKEN_NAME
	} else if data.AccessToken != nil && *data.AccessToken != "" {
		tokenStr = *data.AccessToken
		tokenType = tg.ACCESS_TOKEN_NAME
	} else {
		// If not in request body, check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || !strings.HasPrefix(authHeader, "Bearer ") {
			slog.Error("No token found in request body or Authorization header")
			return &Response{
				Code: http.StatusBadRequest,
				body: "Missing token - provide either in request body or Authorization header",
			}
		}
		tokenStr = authHeader[7:] // Remove "Bearer " prefix
		tokenType = tg.ACCESS_TOKEN_NAME
	}

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the user switch
	switchRequest := loginflow.UserSwitchRequest{
		TokenString:          tokenStr,
		TokenType:            tokenType,
		TargetUserID:         data.UserID,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprintData,
		DeviceFingerprintStr: fingerprintStr,
	}

	result := h.loginFlowService.ProcessUserSwitch(r.Context(), switchRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		switch result.ErrorResponse.Type {
		case "forbidden":
			return PostMobileUserSwitchJSON403Response(struct {
				Message *string `json:"message,omitempty"`
			}{
				Message: ptr(result.ErrorResponse.Message),
			})
		case "unauthorized":
			return &Response{
				Code: http.StatusUnauthorized,
				body: result.ErrorResponse.Message,
			}
		case "invalid_token":
			return &Response{
				Code: http.StatusUnauthorized,
				body: result.ErrorResponse.Message,
			}
		default:
			return &Response{
				Code: http.StatusInternalServerError,
				body: result.ErrorResponse.Message,
			}
		}
	}

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(result.Tokens)
}

// Get a list of users associated with the current login
// (GET /mobile/users)
func (h Handle) MobileFindUsersWithLogin(w http.ResponseWriter, r *http.Request, params MobileFindUsersWithLoginParams) *Response {
	var tokenStr string
	var tokenType string
	if params.TempToken != nil && *params.TempToken != "" {
		tokenStr = *params.TempToken
		tokenType = tg.TEMP_TOKEN_NAME
	} else if params.AccessToken != nil && *params.AccessToken != "" {
		tokenStr = *params.AccessToken
		tokenType = tg.ACCESS_TOKEN_NAME
	} else {
		// If not in request body, check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || !strings.HasPrefix(authHeader, "Bearer ") {
			slog.Error("No token found in request body or Authorization header")
			return &Response{
				Code: http.StatusBadRequest,
				body: "Missing token - provide either in request body or Authorization header",
			}
		}
		tokenStr = authHeader[7:] // Remove "Bearer " prefix
		tokenType = tg.ACCESS_TOKEN_NAME
	}

	// Use loginflow service to process the mobile user lookup
	lookupRequest := loginflow.MobileUserLookupRequest{
		TokenString: tokenStr,
		TokenType:   tokenType,
	}

	result := h.loginFlowService.ProcessMobileUserLookup(r.Context(), lookupRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	return h.responseHandler.PrepareUserListResponse(result.Users)
}

// Helper function to create a pointer to a string
func ptr(s string) *string {
	return &s
}

// Helper functions to extract request information
func getIPAddressFromRequest(r *http.Request) string {
	// Try X-Forwarded-For header first (for clients behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP header next
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If there's an error, just return the RemoteAddr as is
		return r.RemoteAddr
	}
	return ip
}

func getUserAgentFromRequest(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// GetDeviceExpiration returns the device expiration days
// (GET /device/expiration)
func (h Handle) GetDeviceExpiration(w http.ResponseWriter, r *http.Request) *Response {
	deviceExpiration := h.loginFlowService.GetDeviceExpiration()
	days := int(deviceExpiration.Hours() / 24)
	return &Response{
		Code: http.StatusOK,
		body: map[string]interface{}{
			"expiration_days": days,
			"message":         fmt.Sprintf("Remember this device for %d days.", days),
		},
		contentType: "application/json",
	}
}

// InitiateMagicLinkLogin handles requests for magic link login
// (POST /login/magic-link)
func (h Handle) InitiateMagicLinkLogin(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	var request MagicLinkLoginRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	// Generate magic link token
	token, email, err := h.loginService.GenerateMagicLinkToken(r.Context(), request.Username)
	if err != nil {
		// Return success even if user not found to prevent username enumeration
		return &Response{
			Code: http.StatusOK,
			body: map[string]string{
				"message": "If an account exists with that username, we will send a login link to the associated email.",
			},
			contentType: "application/json",
		}
	}

	// Send magic link email
	err = h.loginService.SendMagicLinkEmail(r.Context(), login.SendMagicLinkEmailParams{
		Email:    email,
		Token:    token,
		Username: request.Username,
	})
	if err != nil {
		slog.Error("Failed to send magic link email", "error", err)
		// Return success anyway to prevent username enumeration
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{
			"message": "If an account exists with that username, we will send a login link to the associated email.",
		},
		contentType: "application/json",
	}
}

// 2025-08-25: refactor Login routes to move business logic into service layer
// ValidateMagicLinkToken validates a magic link token and logs the user in
// (GET /login/magic-link/validate)
func (h Handle) ValidateMagicLinkToken(w http.ResponseWriter, r *http.Request, params ValidateMagicLinkTokenParams) *Response {
	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)

	// Use loginflow service to process the magic link validation
	result := h.loginFlowService.ProcessMagicLinkValidation(r.Context(), params.Token, ipAddress, userAgent, fingerprintData)

	// Handle error responses
	if result.ErrorResponse != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"message": result.ErrorResponse.Message,
			},
			contentType: "application/json",
		}
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		h.tokenCookieService.SetTokensCookie(w, result.Tokens)
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Set tokens in cookies for successful login
	err := h.tokenCookieService.SetTokensCookie(w, result.Tokens)
	if err != nil {
		slog.Error("Failed to set tokens cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens cookie",
		}
	}

	// Convert mapped users to API users
	apiUsers := make([]User, len(result.Users))
	for i, mu := range result.Users {
		email := mu.UserInfo.Email
		name := mu.DisplayName

		// Use the Roles field directly - it's always populated and safe
		roles := mu.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
		}
	}

	response := Login{
		Status:  STATUS_SUCCESS,
		Message: "Login successful",
		User:    apiUsers[0],
		Users:   apiUsers,
	}

	return PostLoginJSON200Response(response)
}

// This API is currently unused, similar API has been moved to pkg/profile
// Get a list of users associated with the current login
// (GET /users)
func (h Handle) FindUsersWithLogin(w http.ResponseWriter, r *http.Request) *Response {
	// Get token from cookie instead of Authorization header
	cookie, err := r.Cookie(tg.ACCESS_TOKEN_NAME)
	if err != nil {
		slog.Error("No Access Token Cookie", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Missing access token cookie",
		}
	}
	tokenStr := cookie.Value

	// Use loginflow service to process the user lookup
	lookupRequest := loginflow.MobileUserLookupRequest{
		TokenString: tokenStr,
		TokenType:   tg.ACCESS_TOKEN_NAME,
	}

	result := h.loginFlowService.ProcessMobileUserLookup(r.Context(), lookupRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	return h.responseHandler.PrepareUserListResponse(result.Users)
}
