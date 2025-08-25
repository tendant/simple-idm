package loginapiv2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/common"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/loginflow"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
	LOGOUT_TOKEN_NAME  = "logout_token"
)

type Handle struct {
	loginService     *login.LoginService
	loginFlowService *loginflow.Service
	// twoFactorService   twofa.TwoFactorService
	tokenService       tg.TokenService
	tokenCookieService tg.TokenCookieService
	// userMapper         mapper.UserMapper
	responseHandler ResponseHandler
	// deviceExpirationDays time.Duration
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

func WithLoginFlowService(lfs *loginflow.Service) Option {
	return func(h *Handle) {
		h.loginFlowService = lfs
	}
}

// func WithTwoFactorService(tfs twofa.TwoFactorService) Option {
// 	return func(h *Handle) {
// 		h.twoFactorService = tfs
// 	}
// }

func WithTokenService(ts tg.TokenService) Option {
	return func(h *Handle) {
		h.tokenService = ts
	}
}

func WithTokenCookieService(tcs tg.TokenCookieService) Option {
	return func(h *Handle) {
		h.tokenCookieService = tcs
	}
}

// func WithUserMapper(um mapper.UserMapper) Option {
// 	return func(h *Handle) {
// 		h.userMapper = um
// 	}
// }

func WithResponseHandler(rh ResponseHandler) Option {
	return func(h *Handle) {
		h.responseHandler = rh
	}
}

// WithDeviceExpirationDays sets the device expiration days for the handle
// func WithDeviceExpirationDays(days time.Duration) Option {
// 	return func(h *Handle) {
// 		h.deviceExpirationDays = days
// 	}
// }

// prepare2FARequiredResponse prepares a 2FA required response
// helper method for login handler, private since no need for separate implementation
func (h Handle) prepare2FARequiredResponse(commonMethods []loginflow.TwoFactorMethod, tempTokenStr string) *Response {
	// Convert common.TwoFactorMethod to api.TwoFactorMethod
	var twoFactorMethods []TwoFactorMethod
	err := copier.Copy(&twoFactorMethods, &commonMethods)
	if err != nil {
		slog.Error("Failed to copy 2FA methods", "err", err)
		return &Response{
			body: "Failed to process 2FA methods",
			Code: http.StatusInternalServerError,
		}
	}

	twoFARequiredResp := TwoFactorRequiredResponse{
		TempToken:        tempTokenStr,
		TwoFactorMethods: twoFactorMethods,
		Status:           STATUS_2FA_REQUIRED,
		Message:          "Two-factor authentication is required",
	}

	return &Response{
		Code: http.StatusAccepted,
		body: twoFARequiredResp,
	}
}

// prepareUserAssociationSelectionResponse prepares a response for user association selection
// It generates a temporary token with the necessary claims and returns a properly formatted response
func (h Handle) prepareUserAssociationSelectionResponse(w http.ResponseWriter, loginID, userID string, userOptions []mapper.User) *Response {
	// Prepare extra claims for the temp token
	extraClaims := map[string]interface{}{
		"login_id":     loginID,
		"2fa_verified": true,
	}

	// Add user options to extra claims
	if userOptions == nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "No users found with login provided",
		}
	}

	extraClaims["user_options"] = userOptions

	// Generate a temporary token with the necessary claims
	tempTokenMap, err := h.tokenService.GenerateTempToken(userID, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to generate temp token: " + err.Error(),
		}
	}

	// Set the token cookie if a response writer is provided
	if w != nil {
		err = h.tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to set temp token cookie: " + err.Error(),
			}
		}
	}

	if len(userOptions) > 1 {
		return h.responseHandler.PrepareUserAssociationSelectionResponse(loginID, userOptions)
	}

	user := UserOption{
		UserID:      userOptions[0].UserId,
		DisplayName: userOptions[0].DisplayName,
		Email:       userOptions[0].UserInfo.Email,
	}

	resp := AssociateUserResponse{
		Status:     STATUS_USER_ASSOCIATION_REQUIRED,
		Message:    "Please call user association endpoint",
		LoginID:    loginID,
		UserOption: user,
	}

	return &Response{
		Code:        http.StatusAccepted,
		body:        resp,
		contentType: "application/json",
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
		Username:          data.Username,
		Password:          data.Password,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprintStr,
	}

	result := h.loginFlowService.ProcessLogin(r.Context(), loginRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle 2FA required
	if result.RequiresTwoFA {
		return h.prepare2FARequiredResponse(result.TwoFactorMethods, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Convert mapped users to API users
	apiUsers := make([]User, len(result.Users))
	for i, mu := range result.Users {
		email := mu.UserInfo.Email
		name := mu.DisplayName

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
			Role:  mu.ExtraClaims["roles"].([]string)[0],
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
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the email login
	result := h.loginFlowService.ProcessLoginByEmail(r.Context(), string(data.Email), data.Password, ipAddress, userAgent, fingerprintStr)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle 2FA required
	if result.RequiresTwoFA {
		return h.prepare2FARequiredResponse(result.TwoFactorMethods, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Convert mapped users to API users
	apiUsers := make([]User, len(result.Users))
	for i, mu := range result.Users {
		email := mu.UserInfo.Email
		name := mu.DisplayName

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
			Role:  mu.ExtraClaims["roles"].([]string)[0],
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

	// Validate the refresh token
	token, _, err := h.validateRefreshToken(cookie.Value)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: err.Error(),
		}
	}

	// Get user information from token
	userId, tokenUser, err := h.getUserFromToken(r.Context(), token)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: err.Error(),
		}
	}

	// Generate token claims
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)

	tokens, err := h.tokenService.GenerateTokens(userId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

	err = h.tokenCookieService.SetTokensCookie(w, tokens)
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

// getUserFromToken extracts user information from token claims
// Returns the user ID, user object, and any error
func (h Handle) getUserFromToken(ctx context.Context, token *jwt.Token) (string, mapper.User, error) {
	// Get user ID from claims using the common implementation
	userId, err := common.GetUserIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to extract user ID from token", "err", err)
		return "", mapper.User{}, fmt.Errorf("invalid token: %w", err)
	}

	userUuid, err := uuid.Parse(userId)
	if err != nil {
		slog.Error("Failed to parse user ID", "err", err)
		return "", mapper.User{}, fmt.Errorf("failed to parse user ID: %w", err)
	}

	tokenUser, err := h.userMapper.GetUserByUserID(ctx, userUuid)
	if err != nil {
		slog.Error("Failed to get user by user ID", "err", err, "user_id", userId)
		return "", mapper.User{}, fmt.Errorf("failed to get user by user ID: %w", err)
	}

	// Extract claims from token and add them to the user's extra claims
	tokenUser = h.userMapper.ExtractTokenClaims(tokenUser, token.Claims.(jwt.MapClaims))

	return userId, tokenUser, nil
}

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

	// Validate the refresh token
	token, _, err := h.validateRefreshToken(data.RefreshToken)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: err.Error(),
		}
	}

	// Get user information from token
	userId, tokenUser, err := h.getUserFromToken(r.Context(), token)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: err.Error(),
		}
	}

	// Generate token claims
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)

	tokens, err := h.tokenService.GenerateMobileTokens(userId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

	// Return tokens in response instead of setting cookies
	return h.responseHandler.PrepareTokenResponse(tokens)
}

// validateRefreshToken validates a refresh token and returns the parsed token and claims
// Returns the parsed token, claims, and error if validation fails
func (h Handle) validateRefreshToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	// Parse and validate the refresh token
	token, err := h.tokenService.ParseToken(tokenString)
	if err != nil {
		slog.Error("Invalid refresh token", "err", err)
		return nil, nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Explicitly check token expiration
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("Invalid token claims format")
		return nil, nil, fmt.Errorf("invalid token claims format")
	}

	// Check if token has expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		slog.Error("Missing expiration claim in token")
		return nil, nil, fmt.Errorf("invalid token format: missing expiration")
	}

	expTime := time.Unix(int64(exp), 0)
	if time.Now().After(expTime) {
		slog.Error("Refresh token has expired", "expiry", expTime)
		return nil, nil, fmt.Errorf("refresh token has expired")
	}

	return token, claims, nil
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
		TokenString:       tokenStr,
		TokenType:         "temp_token",
		TargetUserID:      data.UserID,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprintStr,
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

	// Get all users for the current login to return in response
	users, err := h.loginService.GetUsersByLoginId(r.Context(), result.LoginID)
	if err != nil {
		slog.Error("Failed to get users for response", "err", err)
		// Don't fail the request, just return the switched user
		return h.responseHandler.PrepareUserSwitchResponse(result.Users)
	}

	// Convert mapped users to API users (including all available users)
	return h.responseHandler.PrepareUserSwitchResponse(users)
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
		Username:          data.Username,
		Password:          data.Password,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprintStr,
	}

	result := h.loginFlowService.ProcessMobileLogin(r.Context(), loginRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle 2FA required
	if result.RequiresTwoFA {
		return h.prepare2FARequiredResponse(result.TwoFactorMethods, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.Tokens[tg.TEMP_TOKEN_NAME].Token)
	}

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(result.Tokens)
}

func (h Handle) PostLogout(w http.ResponseWriter, r *http.Request) *Response {

	tokenMap, err := h.tokenService.GenerateLogoutToken("", nil, nil)
	if err != nil {
		slog.Error("Failed to generate logout token", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to generate logout token",
		}
	}
	err = h.tokenCookieService.SetTokensCookie(w, tokenMap)
	if err != nil {
		slog.Error("Failed to set logout token cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set logout token cookie",
		}
	}
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

	// Parse and validate token
	token, err := h.tokenService.ParseToken(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid temp token",
		}
	}

	// Extract login ID using the helper method
	loginIdStr, err := common.GetLoginIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to extract login ID from token", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token: " + err.Error(),
		}
	}

	loginId, err := uuid.Parse(loginIdStr)
	if err != nil {
		slog.Error("Failed to parse login ID", "err", err)
		return &Response{
			body: "Failed to parse login ID: " + err.Error(),
			Code: http.StatusBadRequest,
		}
	}

	userId, err := uuid.Parse(data.UserID)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Invalid user_id format",
		}
	}

	err = h.twoFactorService.SendTwoFaNotification(r.Context(), loginId, userId, data.TwofaType, data.DeliveryOption)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to init 2fa: " + err.Error(),
		}
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
		TokenString:       tokenStr,
		TwoFAType:         data.TwofaType,
		Passcode:          data.Passcode,
		RememberDevice:    data.RememberDevice2fa,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprintStr,
	}

	result := h.loginFlowService.Process2FAValidation(r.Context(), validationRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle user association flow
	if result.RequiresUserSelection && len(result.Users) > 0 {
		// Check if this is a user association flow by examining the original token
		token, err := h.tokenService.ParseToken(tokenStr)
		if err == nil {
			isAssociateUser := h.checkAssociateUser(token.Claims)
			if isAssociateUser {
				// Extract user ID from token claims
				userID, err := common.GetUserIDFromClaims(token.Claims)
				if err != nil {
					slog.Error("Failed to extract user ID from token claims", "err", err)
					return &Response{
						Code: http.StatusUnauthorized,
						body: "Invalid token: " + err.Error(),
					}
				}
				return h.prepareUserAssociationSelectionResponse(w, result.LoginID.String(), userID, result.Users)
			}
		}

		// Regular multiple users case
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.TempToken.Token)
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

func (h Handle) checkAssociateUser(claims jwt.Claims) bool {
	if mapClaims, ok := claims.(jwt.MapClaims); ok {
		slog.Info("Claims", "claims", mapClaims)

		// User options are nested inside extra_claims
		if extraClaims, exists := mapClaims["extra_claims"].(map[string]interface{}); exists {
			slog.Info("Extra claims", "extraClaims", extraClaims)

			// Extract user options from extra_claims
			if associateUser, exists := extraClaims["associate_users"]; exists {
				slog.Info("Current 2FA is in associate user flow", "associateUser", associateUser)
				return associateUser.(bool)
			}
		}
	}
	return false
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

	// Parse and validate token
	token, err := h.tokenService.ParseToken(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid temp token",
		}
	}

	// Extract login ID using the helper method
	loginIdStr, err := common.GetLoginIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to extract login ID from token", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token: " + err.Error(),
		}
	}

	loginId, err := uuid.Parse(loginIdStr)
	if err != nil {
		slog.Error("Failed to parse login ID", "err", err)
		return &Response{
			body: "Failed to parse login ID: " + err.Error(),
			Code: http.StatusBadRequest,
		}
	}

	userId, err := uuid.Parse(data.UserID)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Invalid user_id format",
		}
	}

	err = h.twoFactorService.SendTwoFaNotification(r.Context(), loginId, userId, data.TwofaType, data.DeliveryOption)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to init 2fa: " + err.Error(),
		}
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
		TokenString:       tokenStr,
		TwoFAType:         data.TwofaType,
		Passcode:          data.Passcode,
		RememberDevice:    data.RememberDevice2fa,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprintStr,
	}

	result := h.loginFlowService.ProcessMobile2FAValidation(r.Context(), validationRequest)

	// Handle error responses
	if result.ErrorResponse != nil {
		return h.mapErrorToHTTPResponse(result.ErrorResponse)
	}

	// Handle multiple users requiring selection
	if result.RequiresUserSelection {
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.TempToken.Token)
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
		TokenString:       tokenStr,
		TokenType:         tokenType,
		TargetUserID:      data.UserID,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprintStr,
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

	// Parse and validate token
	token, err := h.tokenService.ParseToken(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token",
		}
	}

	if tokenType == tg.TEMP_TOKEN_NAME {
		twofaVerified, err := common.Get2FAVerifiedFromClaims(token.Claims)
		if err != nil || !twofaVerified {
			slog.Error("2FA not verified", "err", err)
			return &Response{
				Code: http.StatusUnauthorized,
				body: "2FA not verified",
			}
		}
	}
	// Extract login ID using the helper method
	loginIdStr, err := common.GetLoginIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to extract login ID from token", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token: " + err.Error(),
		}
	}

	loginId, err := uuid.Parse(loginIdStr)
	if err != nil {
		slog.Error("Failed to parse login ID", "err", err)
		return &Response{
			body: "Failed to parse login ID: " + err.Error(),
			Code: http.StatusBadRequest,
		}
	}

	users, err := h.loginService.GetUsersByLoginId(r.Context(), loginId)
	if err != nil {
		slog.Error("Failed to get users by login ID", "err", err)
		return &Response{
			body: "Failed to get users by login ID",
			Code: http.StatusInternalServerError,
		}
	}

	return h.responseHandler.PrepareUserListResponse(users)
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
	days := h.deviceExpirationDays / 24 / time.Hour
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
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Use loginflow service to process the magic link validation
	result := h.loginFlowService.ProcessMagicLinkValidation(r.Context(), params.Token, ipAddress, userAgent, fingerprintStr)

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
		return h.responseHandler.PrepareUserSelectionResponse(result.Users, result.LoginID, result.TempToken.Token)
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

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
			Role:  mu.ExtraClaims["roles"].([]string)[0],
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

// mapErrorToHTTPResponse maps loginflow service errors to HTTP responses
func (h Handle) mapErrorToHTTPResponse(err *loginflow.Error) *Response {
	switch err.Type {
	case "account_locked":
		return &Response{
			Code:        http.StatusTooManyRequests,
			body:        err.Message,
			contentType: "application/json",
		}
	case "password_expired":
		return &Response{
			Code:        http.StatusForbidden,
			body:        err.Message,
			contentType: "application/json",
		}
	case "invalid_credentials":
		return &Response{
			Code: http.StatusBadRequest,
			body: err.Message,
		}
	case "no_user_found":
		return &Response{
			Code: http.StatusForbidden,
			body: err.Message,
		}
	case "internal_error":
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Message,
		}
	default:
		return &Response{
			Code: http.StatusInternalServerError,
			body: "An unexpected error occurred",
		}
	}
}
