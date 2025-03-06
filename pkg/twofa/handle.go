package twofa

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/mapper"
)

const (
	ACCESS_TOKEN_NAME  = "accessToken"
	REFRESH_TOKEN_NAME = "refreshToken"
)

type JwtService interface {
	ParseTokenStr(tokenStr string) (*jwt.Token, error)
	CreateAccessToken(claimData interface{}) (auth.IdmToken, error)
	CreateRefreshToken(claimData interface{}) (auth.IdmToken, error)
}

type Handle struct {
	twoFaService *TwoFaService
	jwtService   auth.Jwt
	userMapper   mapper.UserMapper
}

func NewHandle(twoFaService *TwoFaService, jwtService auth.Jwt, userMapper mapper.UserMapper) Handle {
	return Handle{
		twoFaService: twoFaService,
		jwtService:   jwtService,
		userMapper:   userMapper,
	}
}

// setTokenCookie sets a cookie with the given token name, value, and expiration
func (h Handle) setTokenCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) {
	tokenCookie := &http.Cookie{
		Name:     tokenName,
		Path:     "/",
		Value:    tokenValue,
		Expires:  expire,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it's sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
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

	// FIXME: read the login id from session cookies
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

	err = h.twoFaService.SendTwoFaNotification(r.Context(), loginId, data.TwofaType, data.DeliveryOption)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to init 2fa: " + err.Error(),
		}
	}

	return Post2faSendJSON200Response(resp)
}

// Authenticate 2fa passcode
// (POST /2fa/validate)
func (h Handle) Post2faValidate(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

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

	data := &Post2faValidateJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	valid, err := h.twoFaService.Validate2faPasscode(r.Context(), loginId, data.TwofaType, data.Passcode)
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
	idmUsers, err := h.userMapper.GetUsers(r.Context(), loginId)
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

	if len(idmUsers) > 1 {
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

		// Create temp token with the custom claims for user selection
		tempToken, err := h.jwtService.CreateTempToken(customClaims)
		if err != nil {
			slog.Error("Failed to create temp token", "loginIdStr", loginIdStr, "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to create temp token",
			}
		}

		// Return 202 response with users to select from
		return Post2faValidateJSON202Response(SelectUserRequiredResponse{
			Status:    "select_user_required",
			Message:   "Multiple users found, please select one",
			TempToken: tempToken.Token,
			Users:     apiUsers,
		})
	}

	// Single user case - proceed with normal flow

	userData := customClaims

	// Create access token
	accessToken, err := h.jwtService.CreateAccessToken(userData)
	if err != nil {
		slog.Error("Failed to create access token", "userData", userData, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create access token",
		}
	}

	// Create refresh token
	refreshToken, err := h.jwtService.CreateRefreshToken(userData)
	if err != nil {
		slog.Error("Failed to create refresh token", "userData", userData, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create refresh token",
		}
	}

	// Set cookies
	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	// Include tokens in response
	resp.Result = "success"

	return Post2faValidateJSON200Response(resp)
}

// Enable an existing 2FA method
// (POST /enable)
func (h Handle) Post2faEnable(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	data := Post2faEnableJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Get login ID from path parameter
	loginId, err := uuid.Parse(data.LoginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	// Find enabled 2FA methods
	err = h.twoFaService.EnableTwoFactor(r.Context(), loginId, string(data.TwofaType))
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Error(),
		}
	}

	return Post2faEnableJSON200Response(resp)
}

// Disable an existing 2FA method
// (POST /disable)
func (h Handle) Post2faDisable(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	data := Post2faEnableJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Get login ID from path parameter
	loginId, err := uuid.Parse(data.LoginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	err = h.twoFaService.DisableTwoFactor(r.Context(), loginId, string(data.TwofaType))
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Error(),
		}
	}

	return Post2faDisableJSON200Response(resp)
}

// Delete a 2FA method
// (DELETE /)
func (h Handle) Delete2fa(w http.ResponseWriter, r *http.Request) *Response {
	return Delete2faJSON200Response(SuccessResponse{})
}
