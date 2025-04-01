package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"golang.org/x/exp/slog"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
	LOGOUT_TOKEN_NAME  = "logout_token"
)

type Handle struct {
	loginService       *login.LoginService
	twoFactorService   twofa.TwoFactorService
	tokenService       tg.TokenService
	tokenCookieService tg.TokenCookieService
	userMapper         mapper.UserMapper
	responseHandler    ResponseHandler
}

func NewHandle(loginService *login.LoginService, tokenService tg.TokenService, tokenCookieService tg.TokenCookieService, userMapper mapper.UserMapper, opts ...Option) Handle {
	h := Handle{
		loginService:       loginService,
		tokenService:       tokenService,
		tokenCookieService: tokenCookieService,
		userMapper:         userMapper,
		responseHandler:    NewDefaultResponseHandler(),
	}
	for _, opt := range opts {
		opt(&h)
	}
	return h
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
		email, _ := mu.ExtraClaims["email"].(string)
		name := mu.DisplayName
		id := mu.UserId

		apiUsers[i] = User{
			ID:    id,
			Email: email,
			Name:  name,
		}
	}

	return PostLoginJSON202Response(SelectUserRequiredResponse{
		Status:    "multiple_users",
		Message:   "Multiple users found, please select one",
		TempToken: tempTokenStr,
		Users:     apiUsers,
	})
}

// PrepareUserListResponse prepares a response for a list of users
func (h *DefaultResponseHandler) PrepareUserListResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email, _ := user.ExtraClaims["email"].(string)
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		role := ""
		if len(user.Roles) > 0 {
			role = user.Roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  role,
			Email: email,
		})
	}
	return FindUsersWithLoginJSON200Response(apiUsers)
}

// PrepareUserSwitchResponse prepares a response for user switch
func (h *DefaultResponseHandler) PrepareUserSwitchResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email, _ := user.ExtraClaims["email"].(string)
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		role := ""
		if len(user.Roles) > 0 {
			role = user.Roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  role,
			Email: email,
		})
	}

	response := Login{
		Status:  "success",
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

// check2FAEnabled checks if 2FA is enabled for the given login ID and returns the 2FA methods if enabled
// Returns: (is2FAEnabled, twoFactorMethods, tempToken, error)
func (h Handle) check2FAEnabled(ctx context.Context, w http.ResponseWriter, loginID uuid.UUID, idmUsers []mapper.User) (bool, []TwoFactorMethod, *tg.TokenValue, error) {
	if h.twoFactorService == nil {
		return false, nil, nil, nil
	}

	enabledTwoFAs, err := h.twoFactorService.FindEnabledTwoFAs(ctx, loginID)
	if err != nil {
		slog.Error("Failed to find enabled 2FA", "loginUuid", loginID, "error", err)
		return false, nil, nil, fmt.Errorf("failed to find enabled 2FA: %w", err)
	}

	if len(enabledTwoFAs) == 0 {
		slog.Info("2FA is not enabled for login, skip 2FA verification", "loginUuid", loginID)
		return false, nil, nil, nil
	}

	slog.Info("2FA is enabled for login, proceed to 2FA verification", "loginUuid", loginID)

	// Convert mapped users to API users for token claims
	apiUsers := make([]User, len(idmUsers))
	for i, mu := range idmUsers {
		// Extract email and name from claims
		email, _ := mu.ExtraClaims["email"].(string)
		name := mu.DisplayName

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
		}
	}

	// If email 2FA is enabled, get unique emails from users
	var twoFactorMethods []TwoFactorMethod
	for _, method := range enabledTwoFAs {
		curMethod := TwoFactorMethod{
			Type: method,
		}
		switch method {
		case twofa.TWO_FACTOR_TYPE_EMAIL:
			options := getUniqueEmailsFromUsers(idmUsers)
			curMethod.DeliveryOptions = options
		default:
			curMethod.DeliveryOptions = []DeliveryOption{}
		}
		twoFactorMethods = append(twoFactorMethods, curMethod)
	}

	extraClaims := map[string]interface{}{
		"login_id": loginID.String(),
		"users":    apiUsers,
	}

	tempTokenMap, err := h.tokenService.GenerateTempToken(idmUsers[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return false, nil, nil, fmt.Errorf("failed to generate temp token: %w", err)
	}

	tempToken := tempTokenMap[tg.TEMP_TOKEN_NAME]

	// Only set cookie if a writer is provided (web flow)
	if w != nil {
		err = h.tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return false, nil, nil, fmt.Errorf("failed to set temp token cookie: %w", err)
		}
	}

	return true, twoFactorMethods, &tempToken, nil
}

// checkMultipleUsers checks if there are multiple users for the login and returns a temp token if needed
// Returns: (isMultipleUsers, tempToken, error)
func (h Handle) checkMultipleUsers(ctx context.Context, w http.ResponseWriter, loginID uuid.UUID, idmUsers []mapper.User) (bool, *tg.TokenValue, error) {
	if len(idmUsers) <= 1 {
		return false, nil, nil
	}

	// Create temp token with the custom claims for user selection
	extraClaims := map[string]interface{}{
		"login_id": loginID.String(),
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

	// Call login service
	loginParams := LoginParams{
		Username: data.Username,
	}
	idmUsers, err := h.loginService.Login(r.Context(), loginParams.Username, data.Password)
	if err != nil {
		slog.Error("Login failed", "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	if len(idmUsers) == 0 {
		slog.Error("No user found after login")
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	// Get the first user
	tokenUser := idmUsers[0]

	// Convert mapped users to API users
	apiUsers := make([]User, len(idmUsers))
	for i, mu := range idmUsers {
		// Extract email and name from claims
		email, _ := mu.ExtraClaims["email"].(string)
		name := mu.DisplayName

		apiUsers[i] = User{
			ID:    mu.UserId,
			Name:  name,
			Email: email,
		}
	}

	// Check if 2FA is enabled for current login
	loginID, err := uuid.Parse(idmUsers[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", idmUsers[0].LoginID, "error", err)
		return &Response{
			body: "Invalid login ID",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if 2FA is enabled
	is2FAEnabled, twoFactorMethods, tempToken, err := h.check2FAEnabled(r.Context(), w, loginID, idmUsers)
	if err != nil {
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if is2FAEnabled {
		twoFARequiredResp := TwoFactorRequiredResponse{
			TempToken:        tempToken.Token,
			TwoFactorMethods: twoFactorMethods,
			Status:           "2fa_required",
			Message:          "2FA verification required",
		}

		return PostLoginJSON202Response(twoFARequiredResp)
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), w, loginID, idmUsers)
	if err != nil {
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

	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set access token cookie", "err", err)
		return &Response{
			body: "Failed to set access token cookie",
			Code: http.StatusInternalServerError,
		}
	}

	response := Login{
		Status:  "success",
		Message: "Login successful",
		User:    apiUsers[0],
		Users:   apiUsers,
	}

	return PostLoginJSON200Response(response)
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
	// Get user ID from claims using the helper method
	userId, err := h.GetUserIDFromClaims(token.Claims)
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

	tokens, err := h.tokenService.GenerateTokens(userId, rootModifications, extraClaims)
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
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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

	// Call login service
	loginParams := LoginParams{
		Username: data.Username,
	}
	idmUsers, err := h.loginService.Login(r.Context(), loginParams.Username, data.Password)
	if err != nil {
		slog.Error("Login failed", "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	if len(idmUsers) == 0 {
		slog.Error("No user found after login")
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	// Check if 2FA is enabled for current login
	loginID, err := uuid.Parse(idmUsers[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", idmUsers[0].LoginID, "error", err)
		return &Response{
			body: "Invalid login ID",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if 2FA is enabled - pass nil for ResponseWriter to skip cookie setting
	is2FAEnabled, twoFactorMethods, tempToken, err := h.check2FAEnabled(r.Context(), nil, loginID, idmUsers)
	if err != nil {
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if is2FAEnabled {
		// Return 2FA required response for mobile
		return PostLoginJSON202Response(TwoFactorRequiredResponse{
			TempToken:        tempToken.Token,
			TwoFactorMethods: twoFactorMethods,
			Status:           "2fa_required",
			Message:          "2FA verification required",
		})
	}

	// Check if there are multiple users - pass nil for ResponseWriter to skip cookie setting
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), nil, loginID, idmUsers)
	if err != nil {
		return &Response{
			body: err.Error(),
			Code: http.StatusInternalServerError,
		}
	}

	if isMultipleUsers {
		// Return user selection response
		return h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginID, tempToken.Token)
	}

	// Create JWT tokens
	tokenUser := idmUsers[0]
	rootModifications, extraClaims := h.loginService.ToTokenClaims(tokenUser)
	tokens, err := h.tokenService.GenerateTokens(tokenUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create tokens",
			Code: http.StatusInternalServerError,
		}
	}

	// Return tokens in response
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
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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

	valid, err := h.twoFactorService.Validate2faPasscode(r.Context(), loginId, data.TwofaType, data.Passcode)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	if !valid {
		return &Response{
			Code: http.StatusBadRequest,
			body: "2fa validation failed",
		}
	}

	// 2FA validation successful, create access and refresh tokens
	// Extract user data from claims to use for token creation
	idmUsers, err := h.userMapper.FindUsersByLoginID(r.Context(), loginId)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to get user roles: " + err.Error(),
		}
	}

	if len(idmUsers) == 0 {
		slog.Error("No user found after 2fa")
		return &Response{
			body: "2fa validation failed",
			Code: http.StatusNotFound,
		}
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), w, loginId, idmUsers)
	if err != nil {
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
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create access token",
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
		ExpirationDays:     &policy.ExpirationDays,
	}

	return GetPasswordResetPolicyJSON200Response(response)
}

func (h Handle) GetUserIDFromClaims(claims jwt.Claims) (string, error) {
	// First try to get from subject
	subject, err := claims.GetSubject()
	if err == nil && subject != "" {
		return subject, nil
	}

	// If subject is empty or not available, try to get from extra claims
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return "", fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("extra_claims has invalid format")
	}

	// Try user_id first, then fall back to other common ID field names
	for _, field := range []string{"user_id", "user_uuid", "userId", "id", "sub"} {
		if idValue, ok := extraClaims[field]; ok {
			if idStr, ok := idValue.(string); ok && idStr != "" {
				return idStr, nil
			}
		}
	}

	return "", fmt.Errorf("user ID not found in token claims")
}

func (h Handle) GetLoginIDFromClaims(claims jwt.Claims) (string, error) {
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return "", fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("extra_claims has invalid format")
	}

	// Look for login_id in extra claims
	loginIDValue, ok := extraClaims["login_id"]
	if !ok {
		return "", fmt.Errorf("login_id not found in token claims")
	}

	loginIDStr, ok := loginIDValue.(string)
	if !ok || loginIDStr == "" {
		return "", fmt.Errorf("login_id is not a valid string")
	}

	return loginIDStr, nil
}

// (POST /mobile/2fa/send)
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
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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

	// Validate the 2FA passcode
	valid, err := h.twoFactorService.Validate2faPasscode(r.Context(), loginId, data.TwofaType, data.Passcode)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	if !valid {
		return &Response{
			Code: http.StatusBadRequest,
			body: "2fa validation failed",
		}
	}

	// 2FA validation successful, get users for the login ID
	idmUsers, err := h.userMapper.FindUsersByLoginID(r.Context(), loginId)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to get user roles: " + err.Error(),
		}
	}

	if len(idmUsers) == 0 {
		slog.Error("No user found after 2fa")
		return &Response{
			body: "2fa validation failed",
			Code: http.StatusNotFound,
		}
	}

	// Check if there are multiple users
	isMultipleUsers, tempToken, err := h.checkMultipleUsers(r.Context(), nil, loginId, idmUsers)
	if err != nil {
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

	tokens, err := h.tokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

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

	// Check if token is in the request body
	if data.TempToken != nil && *data.TempToken != "" {
		tokenStr = *data.TempToken
	} else if data.AccessToken != nil && *data.AccessToken != "" {
		tokenStr = *data.AccessToken
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
	}

	// Parse and validate token
	token, err := h.tokenService.ParseToken(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token",
		}
	}

	// Extract login ID using the helper method
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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

	tokens, err := h.tokenService.GenerateTokens(targetUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

	// Return tokens in response for mobile
	return h.responseHandler.PrepareTokenResponse(tokens)
}

// Get a list of users associated with the current login
// (GET /mobile/users)
func (h Handle) MobileFindUsersWithLogin(w http.ResponseWriter, r *http.Request, params MobileFindUsersWithLoginParams) *Response {
	var tokenStr string
	if params.TempToken != nil && *params.TempToken != "" {
		tokenStr = *params.TempToken
	} else if params.AccessToken != nil && *params.AccessToken != "" {
		tokenStr = *params.AccessToken
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
	}

	// Parse and validate token
	token, err := h.tokenService.ParseToken(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token",
		}
	}

	// Extract login ID using the helper method
	loginIdStr, err := h.GetLoginIDFromClaims(token.Claims)
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
