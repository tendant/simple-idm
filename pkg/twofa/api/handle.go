package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
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
	jwtService   *tg.JwtService
	userMapper   mapper.UserMapper
}

// NewHandle creates a new Handle
func NewHandle(twoFaService twofa.TwoFactorService, jwtService *tg.JwtService, userMapper mapper.UserMapper) *Handle {
	return &Handle{
		twoFaService: twoFaService,
		jwtService:   jwtService,
		userMapper:   userMapper,
	}
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
		users := make([]User, len(idmUsers))
		for i, mu := range idmUsers {
			email, _ := mu.ExtraClaims["email"].(string)
			name := mu.DisplayName
			id := mu.UserId

			users[i] = User{
				ID:    id,
				Email: email,
				Name:  name,
			}
		}

		rootModifications, extraClaims := h.userMapper.ToTokenClaims(idmUsers[0])

		// Create temp token with the custom claims for user selection
		tempTokenStr, tempTokenExpiry, err := h.jwtService.GenerateToken(TEMP_TOKEN_NAME, "", rootModifications, extraClaims)
		if err != nil {
			slog.Error("Failed to create temp token claims", "loginIdStr", loginIdStr, "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to create temp token claims",
			}
		}

		// Set temp token cookie
		err = h.jwtService.CookieSetter.SetCookie(w, tg.TEMP_TOKEN_NAME, tempTokenStr, tempTokenExpiry)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to set temp token cookie",
			}
		}

		// Return 202 response with users to select from
		return Post2faValidateJSON202Response(SelectUserRequiredResponse{
			Status:    "select_user_required",
			Message:   "Multiple users found, please select one",
			TempToken: tempTokenStr,
			Users:     users,
		})
	}

	// Single user case - proceed with normal flow

	user := idmUsers[0]

	rootModifications, extraClaims := h.userMapper.ToTokenClaims(user)

	// Create access token
	accessTokenStr, accessTokenExpiry, err := h.jwtService.GenerateToken(ACCESS_TOKEN_NAME, user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create access token", "user", user, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create access token",
		}
	}

	// Create refresh token
	refreshTokenStr, refreshTokenExpiry, err := h.jwtService.GenerateToken(REFRESH_TOKEN_NAME, user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", user, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create refresh token",
		}
	}

	// Set the access token cookie
	err = h.jwtService.CookieSetter.SetCookie(w, tg.ACCESS_TOKEN_NAME, accessTokenStr, accessTokenExpiry)
	if err != nil {
		slog.Error("Failed to set access token cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set access token cookie",
		}
	}

	// Set the refresh token cookie
	err = h.jwtService.CookieSetter.SetCookie(w, tg.REFRESH_TOKEN_NAME, refreshTokenStr, refreshTokenExpiry)
	if err != nil {
		slog.Error("Failed to set refresh token cookie", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set refresh token cookie",
		}
	}

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
