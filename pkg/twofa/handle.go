package twofa

import (
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JwtService interface {
	ParseTokenStr(tokenStr string) (*jwt.Token, error)
}

type Handle struct {
	twoFaService *TwoFaService
	jwtService   JwtService
}

func NewHandle(twoFaService *TwoFaService, jwtService JwtService) Handle {
	return Handle{
		twoFaService: twoFaService,
		jwtService:   jwtService,
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

	err = h.twoFaService.InitTwoFa(r.Context(), loginId, data.TwofaType, data.Email)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to init 2fa: " + err.Error(),
		}
	}

	return Post2faSendJSON200Response(resp)
}

// Authenticate 2fa passcode
// (POST /2fa)
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

	return Post2faValidateJSON200Response(resp)
}

// Get all enabled 2fas
// (GET /2fa/enabled)
func (h Handle) Get2faEnabled(w http.ResponseWriter, r *http.Request, loginID string) *Response {
	// Get login ID from path parameter
	loginId, err := uuid.Parse(loginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	// Find enabled 2FA methods
	twoFAs, err := h.twoFaService.FindEnabledTwoFAs(r.Context(), loginId)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	return Get2faEnabledJSON200Response(struct {
		N2faMethods []string `json:"2fa_methods,omitempty"`
	}{
		N2faMethods: twoFAs,
	})
}
