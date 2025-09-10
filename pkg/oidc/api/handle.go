package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	openapi_types "github.com/discord-gophers/goapi-gen/types"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/jwks"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/oidc"
)

// AuthorizationCode represents a temporary authorization code
type AuthorizationCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	UserID      string
	ExpiresAt   time.Time
	Used        bool
}

// OidcHandle implements the ServerInterface for OIDC endpoints
type OidcHandle struct {
	clientService *oauth2client.ClientService
	oidcService   *oidc.OIDCService
	jwksService   *jwks.JWKSService
}

// Option configures the OidcHandle
type Option func(*OidcHandle)

// NewOidcHandle creates a new OIDC API handle with required services and optional configurations
func NewOidcHandle(clientService *oauth2client.ClientService, oidcService *oidc.OIDCService, opts ...Option) *OidcHandle {
	h := &OidcHandle{
		clientService: clientService,
		oidcService:   oidcService,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// WithJwksService configures the optional JWKS service
func WithJwksService(js *jwks.JWKSService) Option {
	return func(h *OidcHandle) {
		h.jwksService = js
	}
}

// Authorize implements the OAuth2 authorization endpoint
func (h *OidcHandle) Authorize(w http.ResponseWriter, r *http.Request, params AuthorizeParams) *Response {
	slog.Info("OIDC Authorization request received",
		"client_id", params.ClientID,
		"redirect_uri", params.RedirectURI,
		"response_type", params.ResponseType,
		"scope", params.Scope,
		"state", params.State)

	// Extract access token from HTTP request
	accessToken, err := h.getAccessToken(r)
	if err != nil {
		accessToken = "" // Will be handled by service layer
	}

	// Prepare scope
	scope := ""
	if params.Scope != nil {
		scope = *params.Scope
	}

	// Convert CodeChallengeMethod to *string if present
	var codeChallengeMethod *string
	if params.CodeChallengeMethod != nil {
		method := string(*params.CodeChallengeMethod)
		codeChallengeMethod = &method
	}

	// Build authorization request for service layer
	authReq := oidc.AuthorizationRequest{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		ResponseType:        string(params.ResponseType),
		Scope:               scope,
		State:               params.State,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		AccessToken:         accessToken,
		RequestURL:          r.URL.String(),
	}

	// Process authorization request through service layer
	response := h.oidcService.ProcessAuthorizationRequest(r.Context(), authReq)

	// Handle service response
	if !response.Success {
		if response.RedirectURL != "" {
			// Redirect case (login required)
			slog.Info("Redirecting to login", "login_url", response.RedirectURL)
			w.Header().Set("Location", response.RedirectURL)
			w.WriteHeader(response.HTTPStatus)
			return nil
		} else {
			// Error case
			slog.Error("Authorization request failed", "error", response.ErrorCode, "description", response.ErrorDesc)
			return AuthorizeJSON400Response(struct {
				Error            *string `json:"error,omitempty"`
				ErrorDescription *string `json:"error_description,omitempty"`
			}{
				Error:            stringPtr(response.ErrorCode),
				ErrorDescription: stringPtr(response.ErrorDesc),
			})
		}
	}

	// Success case - redirect to client
	slog.Info("Authorization successful, redirecting to client", "callback_url", response.RedirectURL)
	w.Header().Set("Location", response.RedirectURL)
	w.WriteHeader(response.HTTPStatus)
	return nil
}

// getAccessToken retrieves the access token from the request
func (h *OidcHandle) getAccessToken(r *http.Request) (string, error) {
	// Try to retrieve the token from the Authorization header
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// Format should be: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1], nil
		}
	}

	// Check for both possible cookie names
	if cookie, err := r.Cookie("access_token"); err == nil {
		return cookie.Value, nil
	} else if cookie, err := r.Cookie("accessToken"); err == nil {
		return cookie.Value, nil
	}

	accessToken := r.URL.Query().Get("access_token")

	// If we still don't have a token, return an error
	if accessToken == "" {
		return "", fmt.Errorf("missing access token")
	}
	return accessToken, nil
}

// Token implements the OAuth2 token endpoint
func (h *OidcHandle) Token(w http.ResponseWriter, r *http.Request) *Response {
	slog.Info("OIDC Token request received")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form data", "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to parse form data",
		}
	}

	// Extract parameters and build token request for service layer
	tokenReq := oidc.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		RedirectURI:  r.FormValue("redirect_uri"),
		CodeVerifier: r.FormValue("code_verifier"),
	}

	slog.Info("Token request parameters",
		"grant_type", tokenReq.GrantType,
		"client_id", tokenReq.ClientID,
		"code", tokenReq.Code,
		"redirect_uri", tokenReq.RedirectURI,
		"has_code_verifier", tokenReq.CodeVerifier != "")

	// Process token request through service layer
	response := h.oidcService.ProcessTokenRequest(r.Context(), tokenReq)

	// Handle service response
	if !response.Success {
		slog.Error("Token request failed", "error", response.ErrorCode, "description", response.ErrorDesc)
		return &Response{
			Code: response.HTTPStatus,
			body: response.ErrorDesc,
		}
	}

	// Success case - create token response
	tokenResponse := TokenResponse{
		IDToken:     response.IDToken,
		AccessToken: response.AccessToken,
		TokenType:   response.TokenType,
		ExpiresIn:   response.ExpiresIn,
		Scope:       stringPtr(response.Scope),
	}

	slog.Info("Token exchange successful",
		"client_id", tokenReq.ClientID,
		"scope", response.Scope,
		"id_token", response.IDToken,
		"access_token", response.AccessToken,
		"expires_in", response.ExpiresIn,
		"token_type", response.TokenType,
	)

	return TokenJSON200Response(tokenResponse)
}

// JWKS implements the JWKS endpoint
func (h *OidcHandle) Jwks(w http.ResponseWriter, r *http.Request) *Response {
	slog.Info("JWKS request received")

	// Check if JWKS service is configured
	if h.jwksService == nil {
		slog.Error("JWKS service not configured")
		return &Response{
			Code: http.StatusNotImplemented,
			body: "JWKS endpoint not available",
		}
	}

	// Get JWKS from service
	jwks, err := (*h.jwksService).GetJWKS()
	if err != nil {
		slog.Error("Failed to get JWKS", "error", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to retrieve keys",
		}
	}

	response := JWKSResponse{}

	copier.Copy(&response, &jwks)
	slog.Info("JWKS request successful", "keys", response.Keys)

	return JwksJSON200Response(response)
}

// Userinfo implements the OIDC UserInfo endpoint
func (h *OidcHandle) Userinfo(w http.ResponseWriter, r *http.Request) *Response {
	slog.Info("OIDC UserInfo request received")

	// Extract access token from HTTP request
	accessToken, err := h.getAccessToken(r)
	if err != nil {
		slog.Error("Failed to get access token", "error", err)
		return UserinfoJSON401Response(ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: stringPtr("Missing or invalid access token"),
		})
	}

	// Get user info from service
	serviceUserInfo, err := h.oidcService.GetUserInfo(r.Context(), accessToken)
	if err != nil {
		slog.Error("Failed to get user info", "error", err)
		return UserinfoJSON401Response(ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: stringPtr("Invalid or expired access token"),
		})
	}
	slog.Info("UserInfo request successful", "user_info", serviceUserInfo)

	// Convert service UserInfoResponse to API UserInfoResponse
	apiUserInfo := h.convertToAPIUserInfo(serviceUserInfo)

	// Return user info response
	slog.Info("UserInfo request successful", "user_id", serviceUserInfo.Sub)
	return UserinfoJSON200Response(apiUserInfo)
}

// convertToAPIUserInfo converts service UserInfoResponse to API UserInfoResponse
func (h *OidcHandle) convertToAPIUserInfo(serviceUserInfo *oidc.UserInfoResponse) UserInfoResponse {
	apiUserInfo := UserInfoResponse{
		Sub: serviceUserInfo.Sub,
	}
	// Copy optional fields if they exist
	if serviceUserInfo.Name != nil {
		apiUserInfo.Name = serviceUserInfo.Name
	}
	if serviceUserInfo.Email != nil {
		// Convert string to openapi_types.Email
		email := (*openapi_types.Email)(serviceUserInfo.Email)
		apiUserInfo.Email = email
	}

	return apiUserInfo
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
