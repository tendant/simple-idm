package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
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
	twoFaService       twofa.TwoFactorService
	tokenService       tokengenerator.TokenService
	tokenCookieService tokengenerator.TokenCookieService
	userMapper         mapper.UserMapper
}

// NewHandle creates a new Handle
func NewHandle(twoFaService twofa.TwoFactorService, tokenService tokengenerator.TokenService, tokenCookieService tokengenerator.TokenCookieService, userMapper mapper.UserMapper) *Handle {
	return &Handle{
		twoFaService:       twoFaService,
		tokenService:       tokenService,
		tokenCookieService: tokenCookieService,
		userMapper:         userMapper,
	}
}

// Create a new 2FA method
// (POST /)
func (h Handle) Post2faCreate(w http.ResponseWriter, r *http.Request) *Response {
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

	// Permission check: user can only manage their own 2FA unless they are admin
	if !h.canManageTwoFactor(r, loginId) {
		return &Response{
			Code: http.StatusForbidden,
			body: "forbidden: you can only manage your own 2FA",
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

	// Permission check: user can only manage their own 2FA unless they are admin
	if !h.canManageTwoFactor(r, loginId) {
		return &Response{
			Code: http.StatusForbidden,
			body: "forbidden: you can only manage your own 2FA",
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

	// Permission check: user can only manage their own 2FA unless they are admin
	if !h.canManageTwoFactor(r, loginId) {
		return &Response{
			Code: http.StatusForbidden,
			body: "forbidden: you can only manage your own 2FA",
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

	// Permission check: user can only manage their own 2FA unless they are admin
	if !h.canManageTwoFactor(r, loginId) {
		return &Response{
			Code: http.StatusForbidden,
			body: "forbidden: you can only manage your own 2FA",
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

// canManageTwoFactor checks if the authenticated user can manage 2FA for the given loginId
// Returns true if:
// 1. The user is managing their own 2FA (loginId matches authenticated user's loginId)
// 2. The user has admin or superadmin role
func (h Handle) canManageTwoFactor(r *http.Request, targetLoginId uuid.UUID) bool {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed to get authenticated user from context")
		return false
	}

	// Check if user is managing their own 2FA
	if authUser.LoginID == targetLoginId {
		return true
	}

	// Check if user has admin role using client.IsAdmin()
	// This will check for "admin" or "superadmin" roles (backward compatible)
	if client.IsAdmin(authUser) {
		slog.Info("Admin user managing 2FA for another user",
			"adminLoginId", authUser.LoginID,
			"targetLoginId", targetLoginId,
			"roles", authUser.ExtraClaims.Roles)
		return true
	}

	slog.Warn("User attempted to manage another user's 2FA without permission",
		"userLoginId", authUser.LoginID,
		"targetLoginId", targetLoginId,
		"roles", authUser.ExtraClaims.Roles)
	return false
}
