package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/common"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
)

// Response status constants
const (
	STATUS_SUCCESS                    = "success"
	STATUS_MULTIPLE_USERS             = "multiple_users"
	STATUS_USER_ASSOCIATION_REQUIRED  = "user_association_required"
	STATUS_USER_ASSOCIATION_SELECTION = "user_association_selection_required"
	STATUS_2FA_REQUIRED               = "2fa_required"
	STATUS_ACCOUNT_LOCKED             = "account_locked"
	STATUS_PASSWORD_EXPIRED           = "password_expired"
	STATUS_PASSWORD_ABOUT_TO_EXPIRE   = "password_about_to_expire"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
	LOGOUT_TOKEN_NAME  = "logout_token"
)

type Handle struct {
	loginService         *login.LoginService
	twoFactorService     twofa.TwoFactorService
	tokenService         tg.TokenService
	tokenCookieService   tg.TokenCookieService
	userMapper           mapper.UserMapper
	deviceService        device.DeviceService
	responseHandler      ResponseHandler
	deviceExpirationDays time.Duration
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

func WithTwoFactorService(tfs twofa.TwoFactorService) Option {
	return func(h *Handle) {
		h.twoFactorService = tfs
	}
}

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

func WithUserMapper(um mapper.UserMapper) Option {
	return func(h *Handle) {
		h.userMapper = um
	}
}

func WithDeviceService(ds device.DeviceService) Option {
	return func(h *Handle) {
		h.deviceService = ds
	}
}

func WithResponseHandler(rh ResponseHandler) Option {
	return func(h *Handle) {
		h.responseHandler = rh
	}
}

// WithDeviceExpirationDays sets the device expiration days for the handle
func WithDeviceExpirationDays(days time.Duration) Option {
	return func(h *Handle) {
		h.deviceExpirationDays = days
	}
}

// ResponseHandler defines the interface for handling responses during login
type ResponseHandler interface {
	// PrepareUserSelectionResponse converts IDM users to API users for selection
	PrepareUserSelectionResponse(idmUsers []mapper.User, loginID uuid.UUID, tempTokenStr string) *Response
	// PrepareUserListResponse prepares a response for a list of users
	PrepareUserListResponse(users []mapper.User) *Response
	// PrepareUserSwitchResponse prepares a response for user switch
	PrepareUserSwitchResponse(users []mapper.User) *Response
	// PrepareTokenResponse prepares a response with access and refresh tokens
	PrepareTokenResponse(tokens map[string]tg.TokenValue) *Response
	// PrepareUserAssociationSelectionResponse prepares a response for user association selection
	PrepareUserAssociationSelectionResponse(loginID string, users []mapper.User) *Response
}

// DefaultResponseHandler is the default implementation of ResponseHandler
type DefaultResponseHandler struct {
}

// NewDefaultResponseHandler creates a new DefaultResponseHandler
func NewDefaultResponseHandler() ResponseHandler {
	return &DefaultResponseHandler{}
}

// PrepareUserSelectionResponse creates a response for user selection
func (h *DefaultResponseHandler) PrepareUserSelectionResponse(idmUsers []mapper.User, loginID uuid.UUID, tempTokenStr string) *Response {
	apiUsers := make([]User, len(idmUsers))
	for i, mu := range idmUsers {
		email := mu.UserInfo.Email
		name := mu.DisplayName
		id := mu.UserId

		// Use the Roles field directly - it's always populated and safe
		roles := mu.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers[i] = User{
			ID:    id,
			Email: email,
			Name:  name,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
		}
	}

	return PostLoginJSON202Response(SelectUserRequiredResponse{
		Status:    STATUS_MULTIPLE_USERS,
		Message:   "Multiple users found, please select one",
		TempToken: tempTokenStr,
		Users:     apiUsers,
	})
}

// PrepareUserListResponse prepares a response for a list of users
func (h *DefaultResponseHandler) PrepareUserListResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email := user.UserInfo.Email
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		// Use the Roles field directly - it's always populated and safe
		roles := user.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
			Email: email,
		})
	}
	return FindUsersWithLoginJSON200Response(apiUsers)
}

// PrepareUserSwitchResponse prepares a response for user switch
func (h *DefaultResponseHandler) PrepareUserSwitchResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email := user.UserInfo.Email
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		// Use the Roles field directly - it's always populated and safe
		roles := user.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
			Email: email,
		})
	}

	response := Login{
		Status:  STATUS_SUCCESS,
		Message: "Successfully switched user",
		Users:   apiUsers,
	}

	return PostUserSwitchJSON200Response(response)
}

// PrepareTokenResponse creates a response with access and refresh tokens
func (h *DefaultResponseHandler) PrepareTokenResponse(tokens map[string]tg.TokenValue) *Response {
	accessToken, hasAccess := tokens[tg.ACCESS_TOKEN_NAME]
	refreshToken, hasRefresh := tokens[tg.REFRESH_TOKEN_NAME]

	if !hasAccess || !hasRefresh {
		slog.Error("Missing required tokens", "has_access", hasAccess, "has_refresh", hasRefresh)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Internal server error: insufficient tokens",
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: LoginResponse{
			AccessToken:  accessToken.Token,
			RefreshToken: refreshToken.Token,
		},
		contentType: "application/json",
	}
}

// PrepareUserAssociationSelectionResponse prepares a response for user association selection
func (h *DefaultResponseHandler) PrepareUserAssociationSelectionResponse(loginID string, users []mapper.User) *Response {
	// Convert mapper.User objects to UserOption objects
	var userOptions []UserOption
	for _, user := range users {
		option := UserOption{
			UserID:      user.UserId,
			DisplayName: user.DisplayName,
			Email:       user.UserInfo.Email,
		}

		userOptions = append(userOptions, option)
	}

	// Prepare the response with user options for selection
	resp := SelectUsersToAssociateRequiredResponse{
		Status:      STATUS_USER_ASSOCIATION_SELECTION,
		Message:     "Please select users to associate",
		LoginID:     loginID,
		UserOptions: userOptions,
	}

	slog.Info("Returning user selection options", "login_id", loginID, "option_count", len(users))
	return &Response{
		Code:        http.StatusAccepted,
		body:        resp,
		contentType: "application/json",
	}
}

// prepare2FARequiredResponse prepares a 2FA required response
// helper method for login handler, private since no need for separate implementation
func (h Handle) prepare2FARequiredResponse(commonMethods []common.TwoFactorMethod, tempToken *tg.TokenValue) *Response {
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
		TempToken:        tempToken.Token,
		TwoFactorMethods: twoFactorMethods,
		Status:           STATUS_2FA_REQUIRED,
		Message:          "Two-factor authentication is required",
	}

	return &Response{
		Code: http.StatusAccepted,
		body: twoFARequiredResp,
	}
}

// checkMultipleUsers checks if there are multiple users for the login and returns a temp token if needed
// Returns: (isMultipleUsers, tempToken, error)
func (h Handle) checkMultipleUsers(ctx context.Context, w http.ResponseWriter, loginID uuid.UUID, idmUsers []mapper.User) (bool, *tg.TokenValue, error) {
	if len(idmUsers) <= 1 {
		return false, nil, nil
	}

	// Create temp token with the custom claims for user selection
	extraClaims := map[string]interface{}{
		"login_id":     loginID.String(),
		"2fa_verified": true, // This method will only be called if 2FA is not enabled or 2FA validation is passed
	}
	tempTokenMap, err := h.tokenService.GenerateTempToken(idmUsers[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return true, nil, fmt.Errorf("failed to generate temp token: %w", err)
	}

	// Only set cookie if a writer is provided (web flow)
	if w != nil {
		err = h.tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return true, nil, fmt.Errorf("failed to set temp token cookie: %w", err)
		}
	}

	tempToken := tempTokenMap[tg.TEMP_TOKEN_NAME]
	return true, &tempToken, nil
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
	passwordHash, err := h.loginService.GetPasswordManager().HashPassword(data.Password)
	if err != nil {
		slog.Error("Failed to hash password for logging", "err", err)
		passwordHash = "hash_error"
	}
	slog.Info("Login request", "username", data.Username, "password_hash", passwordHash)

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Call login service
	loginParams := LoginParams{
		Username: data.Username,
	}
	loginResult, err := h.loginService.Login(r.Context(), loginParams.Username, data.Password)

	if err != nil {
		slog.Error("Login failed", "err", err)

		// Record the login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, loginResult.FailureReason)

		// Check if this is an account lockout error
		if login.IsAccountLockedError(err) {
			// Return a standardized response for account lockout
			lockoutDuration := h.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)
			return &Response{
				Code:        http.StatusTooManyRequests, // 429 is appropriate for rate limiting/lockout
				body:        "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				contentType: "application/json",
			}
		}

		// Check if this is a password expiration error
		if strings.Contains(err.Error(), "password has expired") {
			return &Response{
				Code:        http.StatusForbidden,
				body:        "Your password has expired and must be changed before you can log in.",
				contentType: "application/json",
			}
		}

		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	idmUsers := loginResult.Users
	if len(idmUsers) == 0 {
		slog.Error("No user found after login")
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)
		return &Response{
			body: "Account not active",
			Code: http.StatusForbidden,
		}
	}

	// Get the first user
	tokenUser := idmUsers[0]

	// Convert mapped users to API users
	apiUsers := make([]User, len(idmUsers))
	for i, mu := range idmUsers {
		// Extract email and name from claims
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

	// Check if 2FA is enabled for current login
	loginID, err := uuid.Parse(idmUsers[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", idmUsers[0].LoginID, "error", err)
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: "Invalid login ID",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if the device is recognized for this login
	deviceRecognized := false

	if fingerprintStr != "" {
		// Check if this device is linked to the login
		loginDevice, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), fingerprintStr, loginID)
		if err == nil && !loginDevice.IsExpired() {
			// Device is recognized and not expired, skip 2FA
			slog.Info("Device recognized, skipping 2FA", "fingerprint", fingerprintStr, "loginID", loginID)
			deviceRecognized = true
		}
	}

	if !deviceRecognized {
		// Check if 2FA is enabled
		enabled, commonMethods, tempToken, err := common.Check2FAEnabled(
			r.Context(),
			w,
			loginID,
			idmUsers,
			h.twoFactorService,
			h.tokenService,
			h.tokenCookieService,
			false, // Not associate user in this API
		)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			// Record failed login attempt
			h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
			return &Response{
				body: err.Error(),
				Code: http.StatusInternalServerError,
			}
		}

		if enabled {
			// Return 2FA required response
			return h.prepare2FARequiredResponse(commonMethods, tempToken)
		}
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), w, loginID, idmUsers)
	if err != nil {
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		// Prepare user selection response
		respBody := h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginID, tempToken.Token)
		return respBody
	}

	// Create JWT tokens using the JwtService
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)

	tokens, err := h.tokenService.GenerateTokens(tokenUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to set access token cookie", "err", err)
		return &Response{
			body: "Failed to set access token cookie",
			Code: http.StatusInternalServerError,
		}
	}

	// Set tokens in cookies
	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set access token cookie", "err", err)
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: "Failed to set access token cookie",
			Code: http.StatusInternalServerError,
		}
	}

	// Record successful login attempt
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginID, ipAddress, userAgent, fingerprintStr)

	// Create response with user information
	response := Login{
		Status:  STATUS_SUCCESS,
		Message: "Login successful",
		User:    apiUsers[0],
		Users:   apiUsers,
	}

	return PostLoginJSON200Response(response)
}

// 2025-08-11: Added a set of functions to handle login by email
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
	passwordHash, err := h.loginService.GetPasswordManager().HashPassword(data.Password)
	if err != nil {
		slog.Error("Failed to hash password for logging", "err", err)
		passwordHash = "hash_error"
	}
	slog.Info("Email login request", "email", data.Email, "password_hash", passwordHash)

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Call login service with email
	loginResult, err := h.loginService.LoginByEmail(r.Context(), string(data.Email), data.Password)

	if err != nil {
		slog.Error("Email login failed", "err", err)

		// Record the login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, loginResult.FailureReason)

		// Check if this is an account lockout error
		if login.IsAccountLockedError(err) {
			// Return a standardized response for account lockout
			lockoutDuration := h.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)
			return &Response{
				Code:        http.StatusTooManyRequests, // 429 is appropriate for rate limiting/lockout
				body:        "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				contentType: "application/json",
			}
		}

		// Check if this is a password expiration error
		if strings.Contains(err.Error(), "password has expired") {
			return &Response{
				Code:        http.StatusForbidden,
				body:        "Your password has expired and must be changed before you can log in.",
				contentType: "application/json",
			}
		}

		return &Response{
			body: "Email/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	idmUsers := loginResult.Users
	if len(idmUsers) == 0 {
		slog.Error("No user found after email login")
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)
		return &Response{
			body: "Account not active",
			Code: http.StatusForbidden,
		}
	}

	// Get the first user
	tokenUser := idmUsers[0]
	// Convert mapped users to API users
	apiUsers := make([]User, len(idmUsers))
	for i, mu := range idmUsers {
		// Extract email and name from claims
		email := mu.UserInfo.Email
		name := mu.DisplayName

		// Use the Roles field directly - it's always populated and safe
		roles := mu.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers[i] = User{
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
			ID:    mu.UserId,
			Name:  name,
			Email: email,
		}
	}

	// Check if 2FA is enabled for current login
	loginID, err := uuid.Parse(idmUsers[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", idmUsers[0].LoginID, "error", err)
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: "Invalid login ID",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if the device is recognized for this login
	deviceRecognized := false

	if fingerprintStr != "" {
		// Check if this device is linked to the login
		loginDevice, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), fingerprintStr, loginID)
		if err == nil && !loginDevice.IsExpired() {
			// Device is recognized and not expired, skip 2FA
			slog.Info("Device recognized, skipping 2FA", "fingerprint", fingerprintStr, "loginID", loginID)
			deviceRecognized = true
		}
	}

	if !deviceRecognized {
		// Check if 2FA is enabled
		enabled, commonMethods, tempToken, err := common.Check2FAEnabled(
			r.Context(),
			w,
			loginID,
			idmUsers,
			h.twoFactorService,
			h.tokenService,
			h.tokenCookieService,
			false, // Not associate user in this API
		)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			// Record failed login attempt
			h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
			return &Response{
				body: err.Error(),
				Code: http.StatusInternalServerError,
			}
		}

		if enabled {
			// Return 2FA required response
			return h.prepare2FARequiredResponse(commonMethods, tempToken)
		}
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), w, loginID, idmUsers)
	if err != nil {
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		// Prepare user selection response
		respBody := h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginID, tempToken.Token)
		return respBody
	}

	// Create JWT tokens using the JwtService
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)

	tokens, err := h.tokenService.GenerateTokens(tokenUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to set access token cookie", "err", err)
		return &Response{
			body: "Failed to set access token cookie",
			Code: http.StatusInternalServerError,
		}
	}

	// Set tokens in cookies
	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set access token cookie", "err", err)
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: "Failed to set access token cookie",
			Code: http.StatusInternalServerError,
		}
	}

	// Record successful login attempt
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginID, ipAddress, userAgent, fingerprintStr)

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

	// Parse and validate token
	token, err := h.tokenService.ParseToken(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid access token",
		}
	}

	// Get login ID from token claims
	loginIdStr, err := common.GetLoginIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to get login ID from claims", "err", err)
		return &Response{
			body: "Failed to get login ID from claims",
			Code: http.StatusBadRequest,
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
			body: "Your session has expired. Please start the login process again.",
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

	twofaVerified, err := common.Get2FAVerifiedFromClaims(token.Claims)
	if err != nil || !twofaVerified {
		slog.Error("2FA not verified", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "2FA not verified",
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

	var ipAddress string
	var userAgent string
	var fingerprintStr string

	ipAddress = getIPAddressFromRequest(r)
	userAgent = getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr = device.GenerateFingerprint(fingerprintData)

	// Get all users for the current login
	users, err := h.loginService.GetUsersByLoginId(r.Context(), loginId)
	if err != nil {
		slog.Error("Failed to get users", "err", err)
		return &Response{
			body: "Failed to get users",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if the requested user is in the list
	var targetUser mapper.User
	found := false
	for _, user := range users {
		if user.UserId == data.UserID {
			targetUser = user
			found = true
			break
		}
	}

	if !found {
		return &Response{
			Code: http.StatusForbidden,
			body: "Not authorized to switch to this user",
		}
	}

	rootModifications, extraClaims := h.loginService.ToTokenClaims(targetUser)

	tokens, err := h.tokenService.GenerateTokens(targetUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set tokens in cookies", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens in cookies",
		}
	}
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginId, ipAddress, userAgent, fingerprintStr)

	// Convert mapped users to API users (including all available users)
	return h.responseHandler.PrepareUserSwitchResponse(users)
}

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

	// Call login service
	loginParams := LoginParams{
		Username: data.Username,
	}
	loginResult, err := h.loginService.Login(r.Context(), loginParams.Username, data.Password)

	if err != nil {
		slog.Error("Login failed", "err", err)

		// Record the login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, loginResult.FailureReason)

		// Check if this is an account lockout error
		if login.IsAccountLockedError(err) {
			// Return a standardized response for account lockout
			return &Response{
				Code:        http.StatusTooManyRequests,                                                  // 429 is appropriate for rate limiting/lockout
				body:        "Your account has been temporarily locked. Please try again in 15 minutes.", // FIX-ME: hard code for now
				contentType: "application/json",
			}
		}

		// Check if this is a password expiration error
		if strings.Contains(err.Error(), "password has expired") {
			return &Response{
				Code:        http.StatusForbidden,
				body:        "Your password has expired and must be changed before you can log in.",
				contentType: "application/json",
			}
		}

		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	idmUsers := loginResult.Users
	if len(idmUsers) == 0 {
		slog.Error("No user found after login")

		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	// Check if 2FA is enabled for current login
	loginID, err := uuid.Parse(idmUsers[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", idmUsers[0].LoginID, "error", err)

		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)

		return &Response{
			body: "Invalid login ID",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if the device is recognized for this login
	deviceRecognized := false

	if fingerprintStr != "" {
		// Check if this device is linked to the login
		loginDevice, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), fingerprintStr, loginID)
		if err == nil && !loginDevice.IsExpired() {
			// Device is recognized and not expired, skip 2FA
			slog.Info("Device recognized, skipping 2FA", "fingerprint", fingerprintStr, "loginID", loginID)
			deviceRecognized = true
		}
	}

	if !deviceRecognized {
		// Check if 2FA is enabled - pass nil for ResponseWriter to skip cookie setting
		enabled, commonMethods, tempToken, err := common.Check2FAEnabled(
			r.Context(),
			nil,
			loginID,
			idmUsers,
			h.twoFactorService,
			h.tokenService,
			h.tokenCookieService,
			false, // Not associate user in this API
		)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)

			// Record failed login attempt
			h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)

			return &Response{
				body: err.Error(),
				Code: http.StatusInternalServerError,
			}
		}

		if enabled {
			// Return 2FA required response
			return h.prepare2FARequiredResponse(commonMethods, tempToken)
		}
	}

	// Check if there are multiple users - pass nil for ResponseWriter to skip cookie setting
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), nil, loginID, idmUsers)
	if err != nil {

		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)

		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		return h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginID, tempToken.Token)
	}

	// Create JWT tokens
	tokenUser := idmUsers[0]
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)
	tokens, err := h.tokenService.GenerateMobileTokens(tokenUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "user", tokenUser, "err", err)

		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)

		return &Response{
			body: "Failed to create tokens",
			Code: http.StatusInternalServerError,
		}
	}
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginID, ipAddress, userAgent, fingerprintStr)

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(tokens)
}

// Register a new user
// (POST /register)
func (h Handle) PostRegister(w http.ResponseWriter, r *http.Request) *Response {
	data := PostRegisterJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Convert to domain RegisterParam type
	registerParam := login.RegisterParam{
		Email:    data.Email,
		Name:     data.Name,
		Password: data.Password,
	}

	// Domain service returns user and error
	_, err = h.loginService.Create(r.Context(), registerParam)
	if err != nil {
		slog.Error("Failed to register user", "email", registerParam.Email, "err", err)
		return &Response{
			body: "Failed to register user",
			Code: http.StatusInternalServerError,
		}
	}
	return &Response{
		Code: http.StatusOK,
		body: "User registered successfully",
	}
}

// Verify email address
// (POST /email/verify)
func (h Handle) PostEmailVerify(w http.ResponseWriter, r *http.Request) *Response {
	data := PostEmailVerifyJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	email := data.Email
	err = h.loginService.EmailVerify(r.Context(), email)
	if err != nil {
		slog.Error("Failed to verify user", "email", email, "err", err)
		return &Response{
			body: "Failed to verify user",
			Code: http.StatusInternalServerError,
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: "User verified successfully",
	}
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
			body: "Your session has expired. Please start the login process again.",
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
			body: "Your session has expired. Please start the login process again.",
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

	data := &Post2faValidateJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	var ipAddress string
	var userAgent string
	var fingerprintStr string

	ipAddress = getIPAddressFromRequest(r)
	userAgent = getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr = device.GenerateFingerprint(fingerprintData)

	valid, err := h.twoFactorService.Validate2faPasscode(r.Context(), loginId, data.TwofaType, data.Passcode)
	if err != nil {
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		// 2025-07-15: we do not increment failed attempts if error occurs due to internal error
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	if !valid {
		// Record failed 2FA validation attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		// 2025-07-15: we increment failed attempts when passcode is invalid
		locked, _, err := h.loginService.IncrementFailedAttemptsAndCheckLock(r.Context(), loginId)
		if err != nil {
			slog.Error("Failed to increment failed attempts", "err", err)
		}
		if locked {
			lockoutDuration := h.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)
			return &Response{
				Code:        http.StatusTooManyRequests, // 429 is appropriate for rate limiting/lockout
				body:        "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				contentType: "application/json",
			}
		}
		return &Response{
			Code: http.StatusBadRequest,
			body: "2fa validation failed",
		}
	}

	// if user selects to remember device, link device to login
	slog.Info("User selected to remember device", "remember_device_2fa", data.RememberDevice2fa)
	if data.RememberDevice2fa {
		common.RememberDevice(r, loginId, h.deviceService)
	}

	// 2FA validation successful, get users by login ID
	idmUsers, err := h.userMapper.FindUsersByLoginID(r.Context(), loginId)
	if err != nil {
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to get user roles: " + err.Error(),
		}
	}

	// Extract user options from claims using the helper method
	isAssociateUser := h.checkAssociateUser(token.Claims)

	// If we have user options, return a user association selection required response
	if isAssociateUser {
		// Extract user ID from token claims
		userID, err := common.GetUserIDFromClaims(token.Claims)
		if err != nil {
			slog.Error("Failed to extract user ID from token claims", "err", err)
			h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
			return &Response{
				Code: http.StatusUnauthorized,
				body: "Invalid token: " + err.Error(),
			}
		}
		return h.prepareUserAssociationSelectionResponse(w, loginIdStr, userID, idmUsers)
	}

	if len(idmUsers) == 0 {
		slog.Error("No user found after 2fa")
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)
		return &Response{
			body: "2fa validation failed",
			Code: http.StatusNotFound,
		}
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), w, loginId, idmUsers)
	if err != nil {
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		// Prepare user selection response
		respBody := h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginId, tempToken.Token)
		return respBody
	}

	// Single user case - proceed with normal flow

	user := idmUsers[0]

	rootModifications, extraClaims := h.userMapper.ToTokenClaims(user)

	tokens, err := h.tokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create access token",
		}
	}

	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set tokens cookie", "err", err)
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens cookie",
		}
	}
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginId, ipAddress, userAgent, fingerprintStr)

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
			body: "Your session has expired. Please start the login process again.",
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

// (POST /mobile/2fa/validate)
func (h Handle) PostMobile2faValidate(w http.ResponseWriter, r *http.Request) *Response {
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
			body: "Your session has expired. Please start the login process again.",
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

	var ipAddress string
	var userAgent string
	var fingerprintStr string

	ipAddress = getIPAddressFromRequest(r)
	userAgent = getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr = device.GenerateFingerprint(fingerprintData)

	// Validate the 2FA passcode
	valid, err := h.twoFactorService.Validate2faPasscode(r.Context(), loginId, data.TwofaType, data.Passcode)
	if err != nil {
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		// 2025-07-15: we do not increment failed attempts if error occurs due to internal error
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	if !valid {
		// Record failed 2FA validation attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		// 2025-07-15: we increment failed attempts when passcode is invalid
		locked, _, err := h.loginService.IncrementFailedAttemptsAndCheckLock(r.Context(), loginId)
		if err != nil {
			slog.Error("Failed to increment failed attempts", "err", err)
		}
		if locked {
			lockoutDuration := h.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)
			return &Response{
				Code:        http.StatusTooManyRequests, // 429 is appropriate for rate limiting/lockout
				body:        "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				contentType: "application/json",
			}
		}
		return &Response{
			Code: http.StatusBadRequest,
			body: "2fa validation failed",
		}
	}

	// if user selects to remember device, link device to login
	if data.RememberDevice2fa {
		common.RememberDevice(r, loginId, h.deviceService)
	}

	// 2FA validation successful, get users for the login ID
	idmUsers, err := h.userMapper.FindUsersByLoginID(r.Context(), loginId)
	if err != nil {
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to get user roles: " + err.Error(),
		}
	}

	if len(idmUsers) == 0 {
		slog.Error("No user found after 2fa")
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)
		return &Response{
			body: "2fa validation failed",
			Code: http.StatusNotFound,
		}
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), nil, loginId, idmUsers)
	if err != nil {
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		// Return user selection response
		return h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginId, tempToken.Token)
	}

	// Single user case - proceed with normal flow
	user := idmUsers[0]
	rootModifications, extraClaims := h.loginService.ToTokenClaims(user)
	extraClaims["2fa_verified"] = true

	tokens, err := h.tokenService.GenerateMobileTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		h.loginService.RecordLoginAttempt(r.Context(), loginId, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginId, ipAddress, userAgent, fingerprintStr)

	// Return tokens in response
	return h.responseHandler.PrepareTokenResponse(tokens)
}

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
			Code: http.StatusInternalServerError,
			body: "Invalid login_id format in token",
		}
	}

	var ipAddress string
	var userAgent string
	var fingerprintStr string

	ipAddress = getIPAddressFromRequest(r)
	userAgent = getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr = device.GenerateFingerprint(fingerprintData)

	// Get all users for the current login
	users, err := h.loginService.GetUsersByLoginId(r.Context(), loginId)
	if err != nil {
		slog.Error("Failed to get users", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to get users",
		}
	}

	// Check if the requested user is in the list
	var targetUser mapper.User
	found := false
	for _, user := range users {
		if user.UserId == data.UserID {
			targetUser = user
			found = true
			break
		}
	}

	if !found {
		return PostMobileUserSwitchJSON403Response(struct {
			Message *string `json:"message,omitempty"`
		}{
			Message: ptr("Not authorized to switch to this user"),
		})
	}

	rootModifications, extraClaims := h.loginService.ToTokenClaims(targetUser)

	tokens, err := h.tokenService.GenerateMobileTokens(targetUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginId, ipAddress, userAgent, fingerprintStr)

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(tokens)
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

// recordSuccessfulLoginAndUpdateDevice is a helper method to record a successful login attempt
// and update the device's last login time
func (h Handle) recordSuccessfulLoginAndUpdateDevice(ctx context.Context, loginID uuid.UUID, ipAddress, userAgent, fingerprint string) {
	// Record successful login attempt
	h.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, true, "")

	// Update device last login time
	if &h.deviceService != nil && fingerprint != "" {
		_, err := h.deviceService.UpdateDeviceLastLogin(ctx, fingerprint)
		if err != nil {
			slog.Error("Failed to update device last login time", "error", err, "fingerprint", fingerprint)
			// Don't fail the login if we can't update the last login time
		}
	}
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

// ValidateMagicLinkToken validates a magic link token and logs the user in
// (GET /login/magic-link/validate)
func (h Handle) ValidateMagicLinkToken(w http.ResponseWriter, r *http.Request, params ValidateMagicLinkTokenParams) *Response {
	// Get token from query params
	token := params.Token

	// Validate token
	loginResult, err := h.loginService.ValidateMagicLinkToken(r.Context(), token)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"message": "Invalid or expired token",
			},
			contentType: "application/json",
		}
	}

	// Get IP address and user agent for login attempt recording
	ipAddress := getIPAddressFromRequest(r)
	userAgent := getUserAgentFromRequest(r)
	fingerprintData := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprintData)

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), w, loginResult.LoginID, loginResult.Users)
	if err != nil {
		// Record failed login attempt
		h.loginService.RecordLoginAttempt(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr, false, login.FAILURE_REASON_INTERNAL_ERROR)
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		// Prepare user selection response
		return h.responseHandler.PrepareUserSelectionResponse(loginResult.Users, loginResult.LoginID, tempToken.Token)
	}

	// Single user case - proceed with normal flow
	slog.Info("Single user case - proceed with normal flow", "login_id", loginResult.LoginID, "user_id", loginResult.Users[0].UserId)
	tokenUser := loginResult.Users[0]

	// Create JWT tokens
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)
	tokens, err := h.tokenService.GenerateTokens(tokenUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}
	slog.Info("Tokens created successfully", "login_id", loginResult.LoginID)

	// Set tokens in cookies
	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set tokens cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens cookie",
		}
	}
	slog.Info("Tokens set successfully", "login_id", loginResult.LoginID)

	// Record successful login attempt
	h.recordSuccessfulLoginAndUpdateDevice(r.Context(), loginResult.LoginID, ipAddress, userAgent, fingerprintStr)

	// Create response with user information
	apiUsers := make([]User, len(loginResult.Users))
	for i, mu := range loginResult.Users {
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
