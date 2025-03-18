package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/token"
	"github.com/tendant/simple-idm/pkg/twofa"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
)

// TwoFaHandler returns a http.Handler for twofa API
func TwoFaHandler(h *Handle) http.Handler {
	r := chi.NewRouter()

	// Mount the API endpoints
	r.Post("/send", func(w http.ResponseWriter, r *http.Request) {
		h.Post2faSend(w, r)
	})
	r.Post("/validate", func(w http.ResponseWriter, r *http.Request) {
		h.Post2faValidate(w, r)
	})
	r.Post("/", func(w http.ResponseWriter, r *http.Request) {
		h.Post2faCreate(w, r)
	})
	r.Post("/enable", func(w http.ResponseWriter, r *http.Request) {
		h.Post2faEnable(w, r)
	})
	r.Post("/disable", func(w http.ResponseWriter, r *http.Request) {
		h.Post2faDisable(w, r)
	})
	r.Post("/delete", func(w http.ResponseWriter, r *http.Request) {
		h.Delete2fa(w, r)
	})

	return r
}

type Handle struct {
	twoFaService twofa.TwoFactorService
	jwtConfig    *token.JwtConfig
	userMapper   mapper.UserMapper
}

func NewHandle(twoFaService twofa.TwoFactorService, jwtConfig token.JwtConfig, userMapper mapper.UserMapper) *Handle {
	// Create JwtConfig from jwtService

	return &Handle{
		twoFaService: twoFaService,
		jwtConfig:    &jwtConfig,
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
		HttpOnly: h.jwtConfig.CookieHttpOnly, // Make the cookie HttpOnly
		Secure:   h.jwtConfig.CookieSecure,   // Ensure it's sent over HTTPS
		SameSite: http.SameSiteLaxMode,       // Prevent CSRF
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
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Get user UUID from context (assuming it's set by auth middleware)
	loginIdStr := authUser.LoginId

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

	err = h.twoFaService.SendTwoFaNotification(r.Context(), loginId, userId, data.TwofaType, data.DeliveryOption)
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

	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Get user UUID from context (assuming it's set by auth middleware)
	loginIdStr := authUser.LoginId

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
		// Create temp token using the token package
		tempClaims, err := h.jwtConfig.TempTokenService.CreateToken(authUser)
		if err != nil {
			slog.Error("Failed to create temp token claims", "loginIdStr", loginIdStr, "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to create temp token claims",
			}
		}

		// Convert claims to token string using token package
		tempTokenStr, err := token.CreateTokenStr(h.jwtConfig.Secret, tempClaims)
		if err != nil {
			slog.Error("Failed to create temp token", "loginIdStr", loginIdStr, "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to create temp token",
			}
		}

		tempToken := auth.IdmToken{
			Token:  tempTokenStr,
			Expiry: tempClaims.ExpiresAt.Time,
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

	userData := authUser

	// Create access token using the token package
	accessClaims, err := h.jwtConfig.AccessTokenService.CreateToken(userData)
	if err != nil {
		slog.Error("Failed to create access token claims", "userData", userData, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create access token claims",
		}
	}

	// Convert claims to token string using token package
	accessTokenStr, err := token.CreateTokenStr(h.jwtConfig.Secret, accessClaims)
	if err != nil {
		slog.Error("Failed to create access token", "userData", userData, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create access token",
		}
	}

	accessToken := auth.IdmToken{
		Token:  accessTokenStr,
		Expiry: accessClaims.ExpiresAt.Time,
	}

	// Create refresh token using the token package
	refreshClaims, err := h.jwtConfig.RefreshTokenService.CreateToken(userData)
	if err != nil {
		slog.Error("Failed to create refresh token claims", "userData", userData, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create refresh token claims",
		}
	}

	// Convert claims to token string using token package
	refreshTokenStr, err := token.CreateTokenStr(h.jwtConfig.Secret, refreshClaims)
	if err != nil {
		slog.Error("Failed to create refresh token", "userData", userData, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create refresh token",
		}
	}

	refreshToken := auth.IdmToken{
		Token:  refreshTokenStr,
		Expiry: refreshClaims.ExpiresAt.Time,
	}

	// Set cookies
	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	// Include tokens in response
	resp.Result = "success"

	return Post2faValidateJSON200Response(resp)
}

// Create a new 2FA method
// (POST /)
func (h Handle) Post2faCreate(w http.ResponseWriter, r *http.Request) *Response {
	//TODO: add permission check: who can create 2FA
	var resp SuccessResponse

	data := Post2faCreateJSONRequestBody{}
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

	// Create new 2FA method
	err = h.twoFaService.EnableTwoFactor(r.Context(), loginId, string(data.TwofaType))
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to create 2fa: " + err.Error(),
		}
	}

	// Return success response
	resp.Result = "success"
	return Post2faCreateJSON201Response(resp)
}

// Enable an existing 2FA method
// (POST /enable)
func (h Handle) Post2faEnable(w http.ResponseWriter, r *http.Request) *Response {
	//TODO: add permission check: who can enable 2FA
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
	//TODO: add permission check: who can disable 2FA
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
// (POST /delete)
func (h Handle) Delete2fa(w http.ResponseWriter, r *http.Request) *Response {
	//TODO: add permission check: who can delete 2FA
	var resp SuccessResponse

	data := Delete2faJSONRequestBody{}
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

	twofaId, err := uuid.Parse(*data.TwofaID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid 2fa id",
		}
	}

	err = h.twoFaService.DeleteTwoFactor(r.Context(), twofa.DeleteTwoFactorParams{
		LoginId:       loginId,
		TwoFactorId:   twofaId,
		TwoFactorType: string(data.TwofaType),
	})
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Error(),
		}
	}

	return Delete2faJSON200Response(resp)
}
