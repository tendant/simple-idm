package api

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	return &Response{
		body: SelectUserRequiredResponse{
			Status:    "select_user_required",
			Message:   "Multiple users found, please select one",
			TempToken: tempTokenStr,
			Users:     apiUsers,
		},
		Code: http.StatusAccepted,
	}
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

	if h.twoFactorService != nil {
		enabledTwoFAs, err := h.twoFactorService.FindEnabledTwoFAs(r.Context(), loginID)
		if err != nil {
			slog.Error("Failed to find enabled 2FA", "loginUuid", loginID, "error", err)
			return &Response{
				body: "Failed to find enabled 2FA",
				Code: http.StatusInternalServerError,
			}
		}

		var twoFactorMethods []TwoFactorMethod
		if len(enabledTwoFAs) > 0 {
			slog.Info("2FA is enabled for login, proceed to 2FA verification", "loginUuid", loginID)

			// If email 2FA is enabled, get unique emails from users
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

			tempToken, err := h.tokenService.GenerateTempToken(idmUsers[0].UserId, nil, extraClaims)

			if err != nil {
				slog.Error("Failed to generate temp token", "err", err)
				return &Response{
					body: "Failed to generate temp token",
					Code: http.StatusInternalServerError,
				}
			}

			err = h.tokenCookieService.SetTokensCookie(w, []tg.TokenValue{tempToken})
			if err != nil {
				slog.Error("Failed to set temp token cookie", "err", err)
				return &Response{
					body: "Failed to set temp token cookie",
					Code: http.StatusInternalServerError,
				}
			}

			twoFARequiredResp := TwoFactorRequiredResponse{
				TempToken:        tempToken.Token,
				TwoFactorMethods: twoFactorMethods,
				Status:           "2fa_required",
				Message:          "2FA verification required",
			}

			return PostLoginJSON202Response(twoFARequiredResp)
		} else {
			slog.Info("2FA is not enabled for login, skip 2FA verification", "loginUuid", loginID)
		}
	}

	if len(idmUsers) > 1 {
		// Create temp token with the custom claims for user selection
		extraClaims := map[string]interface{}{
			"login_id": loginID.String(),
		}
		tempToken, err := h.tokenService.GenerateTempToken(idmUsers[0].UserId, nil, extraClaims)
		if err != nil {
			slog.Error("Failed to generate temp token", "err", err)
			return &Response{
				body: "Failed to generate temp token",
				Code: http.StatusInternalServerError,
			}
		}

		err = h.tokenCookieService.SetTokensCookie(w, []tg.TokenValue{tempToken})
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return &Response{
				body: "Failed to set temp token cookie",
				Code: http.StatusInternalServerError,
			}
		}
		// Prepare user selection response
		return h.responseHandler.PrepareUserSelectionResponse(idmUsers, loginID, tempToken.Token)
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

	// Parse and validate the refresh token
	token, err := h.tokenService.ParseToken(cookie.Value)
	if err != nil {
		slog.Error("Invalid Refresh Token Cookie", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid refresh token",
		}
	}

	// Explicitly check token expiration
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("Invalid token claims format")
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token format",
		}
	}

	// Check if token has expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		slog.Error("Missing expiration claim in token")
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token format: missing expiration",
		}
	}

	expTime := time.Unix(int64(exp), 0)
	if time.Now().After(expTime) {
		slog.Error("Refresh token has expired", "expiry", expTime)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Refresh token has expired",
		}
	}

	// Get user ID from claims using the helper method
	userId, err := h.GetUserIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to extract user ID from token", "err", err)
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid token: " + err.Error(),
		}
	}

	userUuid, err := uuid.Parse(userId)
	if err != nil {
		slog.Error("Failed to parse user ID", "err", err)
		return &Response{
			body: "Failed to parse user ID",
			Code: http.StatusBadRequest,
		}
	}
	tokenUser, err := h.userMapper.GetUserByUserID(r.Context(), userUuid)
	if err != nil {
		slog.Error("Failed to get user by user ID", "err", err, "user_id", userId)
		return &Response{
			body: "Failed to get user by user ID",
			Code: http.StatusInternalServerError,
		}
	}

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

// PostMobileLogin handles mobile login requests
// (POST /mobile/login)
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
	return PostMobileLoginJSON200Response(struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  tokens[0].Token,
		RefreshToken: tokens[1].Token,
	})
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

	token, err := h.tokenService.GenerateLogoutToken("", nil, nil)
	if err != nil {
		slog.Error("Failed to generate logout token", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to generate logout token",
		}
	}
	err = h.tokenCookieService.SetTokensCookie(w, []tg.TokenValue{token})
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

// Post2faVerify handles verifying 2FA code during login
// (POST /2fa/verify)
func (h Handle) Post2faVerify(w http.ResponseWriter, r *http.Request) *Response {
	var req TwoFactorVerify
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			body: "Invalid request body",
			Code: http.StatusBadRequest,
		}
	}

	// TODO: Implement 2FA verification logic here
	// This should:
	// 1. Validate the login token
	// 2. Verify the 2FA code
	// 3. Complete the login process if verification succeeds

	return &Response{
		body: Login{
			Message: "2FA verification successful",
			Status:  "success",
			User: User{
				Email: "user@example.com",
				Name:  "User Name",
				ID:    "user-uuid",
			},
		},
		Code: http.StatusOK,
	}
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
