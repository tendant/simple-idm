package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// Handle implements the ServerInterface for OIDC endpoints
type Handle struct {
	clientService *oauth2client.ClientService
	oidcService   *oidc.OIDCService
}

// NewHandle creates a new OIDC API handle
func NewHandle(clientService *oauth2client.ClientService, oidcService *oidc.OIDCService) *Handle {
	return &Handle{
		clientService: clientService,
		oidcService:   oidcService,
	}
}

// Authorize implements the OAuth2 authorization endpoint
func (h *Handle) Authorize(w http.ResponseWriter, r *http.Request, params AuthorizeParams) *Response {
	slog.Info("OIDC Authorization request received",
		"client_id", params.ClientID,
		"redirect_uri", params.RedirectURI,
		"response_type", params.ResponseType,
		"scope", params.Scope,
		"state", params.State)

	// 1. Validate client and request parameters
	scope := ""
	if params.Scope != nil {
		scope = *params.Scope
	}

	client, err := h.clientService.ValidateAuthorizationRequest(
		params.ClientID,
		params.RedirectURI,
		string(params.ResponseType),
		scope,
	)
	if err != nil {
		slog.Error("Invalid authorization request", "error", err)
		return AuthorizeJSON400Response(struct {
			Error            *string `json:"error,omitempty"`
			ErrorDescription *string `json:"error_description,omitempty"`
		}{
			Error:            stringPtr("invalid_request"),
			ErrorDescription: stringPtr(err.Error()),
		})
	}

	// 2. Check if user is authenticated
	accessToken, err := h.getAccessToken(r)
	userClaims, err := h.oidcService.ValidateUserToken(accessToken)
	if err != nil {
		slog.Info("User not authenticated, redirecting to login", "error", err)
		// Build the full authorization URL to redirect back to after login
		authURL := fmt.Sprintf("%s%s", h.oidcService.GetBaseURL(), r.URL.String())
		loginURL := h.buildLoginRedirectURL(authURL)

		slog.Info("Redirecting to login", "login_url", loginURL, "return_url", authURL)

		w.Header().Set("Location", loginURL)
		w.WriteHeader(http.StatusFound)
		return nil
	}

	// 3. Extract user ID from claims
	userID, ok := userClaims["sub"].(string)
	if !ok || userID == "" {
		slog.Error("Missing or invalid subject claim in token")
		return AuthorizeJSON401Response(struct {
			Error            *string `json:"error,omitempty"`
			ErrorDescription *string `json:"error_description,omitempty"`
		}{
			Error:            stringPtr("invalid_token"),
			ErrorDescription: stringPtr("Invalid or missing user ID in token"),
		})
	}

	slog.Info("User authenticated successfully", "user_id", userID, "client_id", client.ClientID)

	// 4. Generate authorization code (with PKCE support if provided)
	var authCode string
	if params.CodeChallenge != nil && *params.CodeChallenge != "" {
		// PKCE flow
		codeChallenge := *params.CodeChallenge
		codeChallengeMethod := "S256" // Default to S256
		if params.CodeChallengeMethod != nil {
			codeChallengeMethod = string(*params.CodeChallengeMethod)
		}

		slog.Info("Using PKCE flow",
			"code_challenge", codeChallenge,
			"code_challenge_method", codeChallengeMethod)

		authCode, err = h.oidcService.GenerateAuthorizationCodeWithPKCE(
			r.Context(), client.ClientID, params.RedirectURI, scope, params.State, userID,
			codeChallenge, codeChallengeMethod)
	} else {
		// Standard flow (backward compatibility)
		authCode, err = h.oidcService.GenerateAuthorizationCode(
			r.Context(), client.ClientID, params.RedirectURI, scope, params.State, userID)
	}

	if err != nil {
		slog.Error("Failed to generate authorization code", "error", err)
		return AuthorizeJSON400Response(struct {
			Error            *string `json:"error,omitempty"`
			ErrorDescription *string `json:"error_description,omitempty"`
		}{
			Error:            stringPtr("server_error"),
			ErrorDescription: stringPtr("Failed to generate authorization code"),
		})
	}

	// 5. Build callback URL and redirect
	callbackURL, err := h.buildCallbackURL(params.RedirectURI, authCode, params.State)
	if err != nil {
		slog.Error("Failed to build callback URL", "error", err)
		return AuthorizeJSON400Response(struct {
			Error            *string `json:"error,omitempty"`
			ErrorDescription *string `json:"error_description,omitempty"`
		}{
			Error:            stringPtr("server_error"),
			ErrorDescription: stringPtr("Failed to build callback URL"),
		})
	}

	slog.Info("Authorization successful, redirecting to client",
		"callback_url", callbackURL,
		"auth_code", authCode,
		"user_id", userID)

	// Redirect back to client with authorization code
	w.Header().Set("Location", callbackURL)
	w.WriteHeader(http.StatusFound)
	return nil
}

// getAccessToken retrieves the access token from the request
func (h *Handle) getAccessToken(r *http.Request) (string, error) {
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

// buildCallbackURL constructs the callback URL with authorization code
func (h *Handle) buildCallbackURL(redirectURI, code string, state *string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("code", code)
	if state != nil && *state != "" {
		q.Set("state", *state)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// buildLoginRedirectURL constructs the login URL with return parameter
func (h *Handle) buildLoginRedirectURL(returnURL string) string {
	// Redirect to the frontend login page (running on port 3000)
	// The frontend will handle the login and redirect back to the OAuth2 flow
	loginURL := fmt.Sprintf("%s?redirect=%s", h.oidcService.GetLoginURL(), url.QueryEscape(returnURL))
	return loginURL
}

// Token implements the OAuth2 token endpoint
func (h *Handle) Token(w http.ResponseWriter, r *http.Request) *Response {
	slog.Info("OIDC Token request received")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form data", "error", err)
		h.writeErrorResponse(w, "invalid_request", "Failed to parse form data", http.StatusBadRequest)
		return nil
	}

	// Extract parameters
	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	slog.Info("Token request parameters",
		"grant_type", grantType,
		"client_id", clientID,
		"code", code,
		"redirect_uri", redirectURI,
		"has_code_verifier", codeVerifier != "")

	// Validate grant type
	if grantType != "authorization_code" {
		slog.Error("Invalid grant type", "grant_type", grantType)
		h.writeErrorResponse(w, "unsupported_grant_type", "Only authorization_code grant type is supported", http.StatusBadRequest)
		return nil
	}

	// Validate required parameters
	if code == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		slog.Error("Missing required parameters")
		h.writeErrorResponse(w, "invalid_request", "Missing required parameters", http.StatusBadRequest)
		return nil
	}

	// Validate client credentials
	client, err := h.clientService.ValidateClientCredentials(clientID, clientSecret)
	if err != nil {
		slog.Error("Invalid client credentials", "error", err, "client_id", clientID)
		h.writeErrorResponse(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return nil
	}

	// Get and validate authorization code (with PKCE support if provided)
	var authCode *oidc.AuthorizationCode
	if codeVerifier != "" {
		// PKCE flow - validate code verifier
		slog.Info("Using PKCE validation", "code_verifier_length", len(codeVerifier))
		authCode, err = h.oidcService.ValidateAndConsumeAuthorizationCodeWithPKCE(r.Context(), code, clientID, redirectURI, codeVerifier)
	} else {
		// Standard flow (backward compatibility)
		authCode, err = h.oidcService.ValidateAndConsumeAuthorizationCode(r.Context(), code, clientID, redirectURI)
	}

	if err != nil {
		slog.Error("Invalid authorization code", "error", err, "code", code)
		h.writeErrorResponse(w, "invalid_grant", "Invalid or expired authorization code", http.StatusBadRequest)
		return nil
	}

	// Generate access token
	accessToken, err := h.oidcService.GenerateAccessToken(r.Context(), authCode.UserID, client.ClientID, authCode.Scope)
	if err != nil {
		slog.Error("Failed to generate access token", "error", err)
		h.writeErrorResponse(w, "server_error", "Failed to generate access token", http.StatusInternalServerError)
		return nil
	}

	refreshToken, err := h.oidcService.GenerateRefreshToken(r.Context(), authCode.UserID, client.ClientID, authCode.Scope)
	if err != nil {
		slog.Error("Failed to generate refresh token", "error", err)
		h.writeErrorResponse(w, "server_error", "Failed to generate refresh token", http.StatusInternalServerError)
		return nil
	}

	// Create token response
	tokenResponse := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: &refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		Scope:        stringPtr(authCode.Scope),
	}

	slog.Info("Token exchange successful",
		"client_id", clientID,
		"user_id", authCode.UserID,
		"scope", authCode.Scope)

	h.writeJSONResponse(w, tokenResponse, http.StatusOK)
	return nil
}

// writeErrorResponse writes an OAuth2 error response
func (h *Handle) writeErrorResponse(w http.ResponseWriter, errorCode, errorDescription string, statusCode int) {
	errorResponse := ErrorResponse{
		Error:            errorCode,
		ErrorDescription: stringPtr(errorDescription),
	}
	h.writeJSONResponse(w, errorResponse, statusCode)
}

// writeJSONResponse writes a JSON response
func (h *Handle) writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
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

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
