package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/twofa"
	"golang.org/x/exp/slog"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
)

type Handle struct {
	loginService     *login.LoginService
	jwtService       auth.Jwt
	twoFactorService twofa.TwoFactorService
}

func NewHandle(loginService *login.LoginService, jwtService auth.Jwt, opts ...Option) Handle {
	h := Handle{
		loginService: loginService,
		jwtService:   jwtService,
	}
	for _, opt := range opts {
		opt(&h)
	}
	return h
}

func (h Handle) setTokenCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) {
	tokenCookie := &http.Cookie{
		Name:     tokenName,
		Path:     "/",
		Value:    tokenValue,
		Expires:  expire,
		HttpOnly: h.jwtService.CoookieHttpOnly, // Make the cookie HttpOnly
		Secure:   h.jwtService.CookieSecure,    // Ensure it’s sent over HTTPS
		SameSite: http.SameSiteLaxMode,         // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
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
			ID:    mu.UserID,
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
			// TODO: set cookies only with login id
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

			tempToken, err := h.jwtService.CreateTempToken(tokenUser)
			if err != nil {
				slog.Error("Failed to create temp token", "loginUuid", loginID, "error", err)
			}

			h.setTokenCookie(w, REFRESH_TOKEN_NAME, tempToken.Token, tempToken.Expiry)
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
		apiUsers := make([]User, len(idmUsers))
		for i, mu := range idmUsers {
			email, _ := mu.ExtraClaims["email"].(string)
			name := mu.DisplayName
			id := mu.UserID

			apiUsers[i] = User{
				ID:    id,
				Email: email,
				Name:  name,
			}
		}

		// Create temp token with the custom claims for user selection
		tempToken, err := h.jwtService.CreateTempToken(tokenUser)
		if err != nil {
			slog.Error("Failed to create temp token", "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to create temp token",
			}
		}

		// Return 202 response with users to select from
		return PostLoginJSON202Response(SelectUserRequiredResponse{
			Status:    "select_user_required",
			Message:   "Multiple users found, please select one",
			TempToken: tempToken.Token,
			Users:     apiUsers,
		})
	}

	// Create JWT tokens
	accessToken, err := h.jwtService.CreateAccessToken(tokenUser)
	if err != nil {
		slog.Error("Failed to create access token", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(tokenUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	// Set cookies and prepare response
	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

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
		return &Response{
			body:        http.StatusText(http.StatusInternalServerError),
			Code:        http.StatusInternalServerError,
			contentType: "html/text",
		}
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

	// FIXME: validate refreshToken
	cookie, err := r.Cookie(REFRESH_TOKEN_NAME)
	if err != nil {
		slog.Error("No Refresh Token Cookie", "err", err)
		return &Response{
			body: "Unauthorized",
			Code: http.StatusUnauthorized,
		}
	}

	claims, err := h.jwtService.ValidateRefreshToken(cookie.Value)
	if err != nil {
		slog.Error("Invalid Refresh Token Cookie", "err", err)
		return &Response{
			body: "Unauthorized",
			Code: http.StatusUnauthorized,
		}
	}

	// Safely extract custom claims
	customClaims, ok := claims["custom_claims"].(map[string]interface{})
	if !ok {
		slog.Error("invalid custom claims format")
		return &Response{
			body: "Unauthorized",
			Code: http.StatusUnauthorized,
		}
	}

	slog.Info("customClaims", "customClaims", customClaims)

	userId, ok := customClaims["user_id"].(string)
	if !ok {
		slog.Error("missing or invalid user_id in claims")
		return &Response{
			body: "Unauthorized",
			Code: http.StatusUnauthorized,
		}
	}

	loginId, ok := customClaims["login_id"].(string)
	if !ok {
		slog.Error("missing or invalid login_id in claims")
		return &Response{
			body: "Unauthorized",
			Code: http.StatusUnauthorized,
		}
	}

	// Initialize empty roles slice
	var roles []string

	// Safely check if role exists in claims
	if roleClaim, exists := customClaims["role"]; exists && roleClaim != nil {
		roleSlice, ok := roleClaim.([]interface{})
		if !ok {
			slog.Error("invalid role format in claims")
			return &Response{
				body: "Unauthorized",
				Code: http.StatusUnauthorized,
			}
		}

		// Convert roles to strings
		for _, r := range roleSlice {
			if strRole, ok := r.(string); ok {
				roles = append(roles, strRole)
			} else {
				slog.Error("invalid role value: not a string")
			}
		}
	} else {
		slog.Info("no roles found in claims")
	}

	// Get display name from claims, default to empty string if not present
	displayName, _ := customClaims["name"].(string)

	// Create the MappedUser object
	mappedUser := mapper.MappedUser{
		LoginID:     loginId,
		UserId:      userId,
		DisplayName: displayName,
		ExtraClaims: customClaims["extra_claims"].(map[string]interface{}),
	}

	accessToken, err := h.jwtService.CreateAccessToken(mappedUser)
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(mappedUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	return &Response{
		Code: http.StatusOK,
		body: "",
	}
}

// Get a list of users associated with the current login
// (GET /users)
func (h Handle) FindUsersWithLogin(w http.ResponseWriter, r *http.Request) *Response {
	// Get bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Missing or invalid Authorization header",
		}
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate token
	token, err := h.jwtService.ParseTokenStr(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid access token",
		}
	}

	// Get claims from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Invalid token claims",
		}
	}

	// Extract login_id from custom_claims
	customClaims, ok := claims["custom_claims"].(map[string]interface{})
	if !ok {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Invalid custom claims format",
		}
	}

	loginIdStr, ok := customClaims["login_id"].(string)
	if !ok {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Missing or invalid login_id in token",
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
	mappedUsers := mapper.ToMappedUsers(users)

	var res []User
	for _, user := range mappedUsers {
		res = append(res, User{
			DeptName:   user.DeptName,
			DeptUUID:   user.DeptUuid.String(),
			TenantName: user.TenantName,
			TenantUUID: user.TenantUuid.String(),
			ID:         user.UserId,
			Name:       user.DisplayName,
			Role:       user.Role,
			Email:      user.Email,
		})
	}

	return FindUsersWithLoginJSON200Response(res)
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

	// Get bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Missing or invalid Authorization header",
		}
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate token
	token, err := h.jwtService.ParseTokenStr(tokenStr)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: "Invalid access token",
		}
	}

	// Get claims from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Invalid token claims",
		}
	}

	// Extract login_id from custom_claims
	customClaims, ok := claims["custom_claims"].(map[string]interface{})
	if !ok {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Invalid custom claims format",
		}
	}

	loginIdStr, ok := customClaims["login_id"].(string)
	if !ok {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Missing or invalid login_id in token",
		}
	}

	loginId, err := uuid.Parse(loginIdStr)
	if err != nil {
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
	var targetUser mapper.MappedUser
	found := false
	for _, user := range users {
		if user.UserID == data.UserID {
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

	// Create new JWT tokens for the target user
	accessToken, err := h.jwtService.CreateAccessToken(targetUser)
	if err != nil {
		slog.Error("Failed to create access token", "user", targetUser, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(targetUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", targetUser, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	// Set cookies and prepare response
	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	// Convert mapped users to API users (including all available users)
	apiUsers := make([]User, len(users))
	for i, mu := range users {
		// Extract email and name from custom claims
		email, _ := mu.ExtraClaims["email"].(string)
		name := mu.DisplayName

		apiUsers[i] = User{
			ID:    mu.UserID,
			Name:  name,
			Email: email,
		}
	}

	response := Login{
		Status:  "success",
		Message: "Successfully switched user",
		Users:   apiUsers,
	}

	return PostUserSwitchJSON200Response(response)
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

	accessToken, err := h.jwtService.CreateAccessToken(tokenUser)
	if err != nil {
		slog.Error("Failed to create access token", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(tokenUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	// Return tokens in response
	return PostMobileLoginJSON200Response(struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
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
	logoutToken, err := h.jwtService.CreateLogoutToken(auth.Claims{})
	if err != nil {
		slog.Error("Failed to create logout token", "err", err)
		return &Response{
			body: "Failed to create logout token",
			Code: http.StatusInternalServerError,
		}
	}

	h.setTokenCookie(w, ACCESS_TOKEN_NAME, logoutToken.Token, logoutToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, logoutToken.Token, logoutToken.Expiry)
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
