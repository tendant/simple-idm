package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
		h.writeErrorResponse(w, "invalid_request", "Failed to parse form data", http.StatusBadRequest)
		return nil
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
		h.writeErrorResponse(w, response.ErrorCode, response.ErrorDesc, response.HTTPStatus)
		return nil
	}

	// Success case - create token response
	tokenResponse := TokenResponse{
		AccessToken:  response.AccessToken,
		RefreshToken: &response.RefreshToken,
		TokenType:    response.TokenType,
		ExpiresIn:    response.ExpiresIn,
		Scope:        stringPtr(response.Scope),
	}

	slog.Info("Token exchange successful",
		"client_id", tokenReq.ClientID,
		"scope", response.Scope)

	h.writeJSONResponse(w, tokenResponse, http.StatusOK)
	return nil
}

// writeErrorResponse writes an OAuth2 error response
func (h *OidcHandle) writeErrorResponse(w http.ResponseWriter, errorCode, errorDescription string, statusCode int) {
	errorResponse := ErrorResponse{
		Error:            errorCode,
		ErrorDescription: stringPtr(errorDescription),
	}
	h.writeJSONResponse(w, errorResponse, statusCode)
}

// writeJSONResponse writes a JSON response
func (h *OidcHandle) writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Simple JSON encoding without external dependencies
	switch v := data.(type) {
	case TokenResponse:
		fmt.Fprintf(w, `{"access_token":"%s","token_type":"%s","expires_in":%d`, v.AccessToken, v.TokenType, v.ExpiresIn)
		if v.Scope != nil {
			fmt.Fprintf(w, `,"scope":"%s"`, *v.Scope)
		}
		if v.RefreshToken != nil {
			fmt.Fprintf(w, `,"refresh_token":"%s"`, *v.RefreshToken)
		}
		fmt.Fprint(w, "}")
	case ErrorResponse:
		fmt.Fprintf(w, `{"error":"%s"`, v.Error)
		if v.ErrorDescription != nil {
			fmt.Fprintf(w, `,"error_description":"%s"`, *v.ErrorDescription)
		}
		if v.ErrorURI != nil {
			fmt.Fprintf(w, `,"error_uri":"%s"`, *v.ErrorURI)
		}
		fmt.Fprint(w, "}")
	}
}

// JWKS implements the JWKS endpoint
func (h *OidcHandle) Jwks(w http.ResponseWriter, r *http.Request) *Response {
	slog.Info("JWKS request received")

	// Check if JWKS service is configured
	if h.jwksService == nil {
		slog.Error("JWKS service not configured")
		h.writeErrorResponse(w, "server_error", "JWKS endpoint not available", http.StatusNotImplemented)
		return nil
	}

	// Get JWKS from service
	jwks, err := (*h.jwksService).GetJWKS()
	if err != nil {
		slog.Error("Failed to get JWKS", "error", err)
		h.writeErrorResponse(w, "server_error", "Failed to retrieve keys", http.StatusInternalServerError)
		return nil
	}

	// Write JWKS response
	h.writeJWKSResponse(w, jwks, http.StatusOK)
	return nil
}

// writeJWKSResponse writes a JWKS JSON response
func (h *OidcHandle) writeJWKSResponse(w http.ResponseWriter, jwks interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Use encoding/json for JWKS response since it's more complex
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		slog.Error("Failed to encode JWKS response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
