package login

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

const (
	ACCESS_TOKEN_NAME  = "accessToken"
	REFRESH_TOKEN_NAME = "refreshToken"
)

type PasswordResetInitJSONRequestBody struct {
	Username string `json:"username"`
}

type PasswordResetJSONRequestBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type Handle struct {
	loginService *LoginService
	jwtService   auth.Jwt
}

func NewHandle(loginService *LoginService, jwtService auth.Jwt) Handle {
	return Handle{
		loginService: loginService,
		jwtService:   jwtService,
	}
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
	data := PostLoginJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	loginParams := LoginParams{}
	copier.Copy(&loginParams, data)
	dbUsers, err := h.loginService.Login(r.Context(), loginParams)
	if err != nil || len(dbUsers) == 0 {
		slog.Error("User does not exist", "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	if len(dbUsers) > 1 {
		slog.Error("Multiple user records with same username", "username", loginParams.Username)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	valid, err := CheckPasswordHash(data.Password, dbUsers[0].Password.String)
	if err != nil {
		slog.Error("Failed checking password hash", "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}
	if !valid {
		slog.Error("Passwords does not match")
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	// Find users related role
	roles, err := h.loginService.FindUserRoles(r.Context(), dbUsers[0].Uuid)
	if err != nil {
		slog.Error("failed to find user roles", "user_uuid", dbUsers[0].Uuid, "err", err)
		return &Response{
			body: "Internal error",
			Code: http.StatusInternalServerError,
		}
	}

	tokenUser := IdmUser{
		UserUuid: dbUsers[0].Uuid.String(),
		Role:     utils.GetValidStrings(roles),
	}

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

	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	response := Login{
		Status:  "success",
		Message: "Login successful",
		User:    User{},
	}
	copier.Copy(&response.User, dbUsers[0])

	return PostLoginJSON200Response(response)
}

func (h Handle) PostPasswordResetInit(w http.ResponseWriter, r *http.Request) *Response {
	var body PasswordResetInitJSONRequestBody

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
		slog.Error("Failed to init password reset", "err", err, "username", body.Username)
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
	var body PasswordResetJSONRequestBody

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
				"message": "Invalid or expired reset token",
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
	cookie, err := r.Cookie("refreshToken")
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

	userUuid, ok := customClaims["user_uuid"].(string)
	if !ok {
		slog.Error("missing or invalid UserUuid in claims")
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

	// Create the IdmUser object
	idmUser := IdmUser{
		UserUuid: userUuid,
		Role:     roles,
	}

	accessToken, err := h.jwtService.CreateAccessToken(idmUser)
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(idmUser)
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

// PostMobileLogin handles mobile login requests
// (POST /mobile/login)
func (h Handle) PostMobileLogin(w http.ResponseWriter, r *http.Request) *Response {
	data := PostLoginJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	loginParams := LoginParams{}
	copier.Copy(&loginParams, data)
	dbUsers, err := h.loginService.Login(r.Context(), loginParams)
	if err != nil || len(dbUsers) == 0 {
		slog.Error("User does not exist", "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	if len(dbUsers) > 1 {
		slog.Error("Multiple user records with same username", "username", loginParams.Username)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	valid, err := CheckPasswordHash(data.Password, dbUsers[0].Password.String)
	if err != nil {
		slog.Error("Failed checking password hash", "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}
	if !valid {
		slog.Error("Passwords does not match")
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusBadRequest,
		}
	}

	// Find users related role
	roles, err := h.loginService.FindUserRoles(r.Context(), dbUsers[0].Uuid)
	if err != nil {
		slog.Error("failed to find user roles", "user_uuid", dbUsers[0].Uuid, "err", err)
		return &Response{
			body: "Internal error",
			Code: http.StatusInternalServerError,
		}
	}

	tokenUser := IdmUser{
		UserUuid: dbUsers[0].Uuid.String(),
		Role:     utils.GetValidStrings(roles),
	}

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

	return PostMobileLoginJSON200Response(struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
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

	// FIXME:hash/encode data.password, then write to database
	registerParam := RegisterParam{}
	copier.Copy(&registerParam, data)

	_, err = h.loginService.Create(r.Context(), registerParam)
	if err != nil {
		slog.Error("Failed to register user", "email", registerParam.Email, "err", err)
		return &Response{
			body: "Failed to register user",
			Code: http.StatusInternalServerError,
		}
	}
	return &Response{
		Code: http.StatusCreated,
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
		username, err := h.loginService.queries.FindUsernameByEmail(r.Context(), string(body.Email))
		if err != nil {
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
		err = h.loginService.SendUsernameEmail(r.Context(), string(body.Email), username.String)
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
