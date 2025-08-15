package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/tendant/simple-idm/pkg/oauth2client"
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
	// JWT Auth for validating user login tokens
	JwtAuth *jwtauth.JWTAuth

	// OAuth2 Client Service
	ClientService *oauth2client.ClientService

	// In-memory storage for authorization codes (temporary solution)
	authCodes map[string]*AuthorizationCode
	codeMutex sync.RWMutex
}

// NewHandle creates a new OIDC API handle
func NewHandle(jwtAuth *jwtauth.JWTAuth, clientService *oauth2client.ClientService) *Handle {
	return &Handle{
		JwtAuth:       jwtAuth,
		ClientService: clientService,
		authCodes:     make(map[string]*AuthorizationCode),
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

	client, err := h.ClientService.ValidateAuthorizationRequest(
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
	userClaims, err := h.validateUserToken(r)
	if err != nil {
		slog.Info("User not authenticated, redirecting to login", "error", err)
		// Build the full authorization URL to redirect back to after login
		authURL := fmt.Sprintf("http://localhost:4000%s", r.URL.String())
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

	// 4. Generate authorization code
	authCode, err := h.generateAuthorizationCode(client.ClientID, params.RedirectURI, scope, params.State, userID)
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

// validateUserToken validates the user's authentication token
func (h *Handle) validateUserToken(r *http.Request) (map[string]interface{}, error) {
	// Try to retrieve the token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	var accessToken string

	if authHeader != "" {
		// Format should be: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			accessToken = parts[1]
		}
	}

	// If no Authorization header, check cookies (most common for web apps)
	if accessToken == "" {
		// Check for both possible cookie names
		if cookie, err := r.Cookie("access_token"); err == nil {
			accessToken = cookie.Value
		} else if cookie, err := r.Cookie("accessToken"); err == nil {
			accessToken = cookie.Value
		}
	}

	// If still no token, check URL parameters (for testing/development)
	if accessToken == "" {
		accessToken = r.URL.Query().Get("access_token")
	}

	// If we still don't have a token, return an error
	if accessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	// Validate the token using JwtAuth
	if h.JwtAuth == nil {
		return nil, fmt.Errorf("JWT authenticator not initialized")
	}

	// Verify the token and get the token object
	token, err := jwtauth.VerifyToken(h.JwtAuth, accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	// Extract claims from the token
	claims, err := token.AsMap(r.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from token: %w", err)
	}

	// Verify that required claims are present
	if claims["sub"] == nil || claims["sub"] == "" {
		return nil, fmt.Errorf("token missing required 'sub' claim")
	}

	return claims, nil
}

// generateAuthorizationCode creates a new authorization code
func (h *Handle) generateAuthorizationCode(clientID, redirectURI, scope string, state *string, userID string) (string, error) {
	// Generate a random code
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	code := hex.EncodeToString(bytes)

	stateStr := ""
	if state != nil {
		stateStr = *state
	}

	// Store the authorization code
	authCode := &AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       stateStr,
		UserID:      userID,
		ExpiresAt:   time.Now().Add(10 * time.Minute), // 10 minutes expiration
		Used:        false,
	}

	h.codeMutex.Lock()
	h.authCodes[code] = authCode
	h.codeMutex.Unlock()

	// Clean up expired codes (simple cleanup)
	go h.cleanupExpiredCodes()

	return code, nil
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
	loginURL := fmt.Sprintf("http://localhost:3000/login?redirect=%s", url.QueryEscape(returnURL))
	return loginURL
}

// cleanupExpiredCodes removes expired authorization codes
func (h *Handle) cleanupExpiredCodes() {
	h.codeMutex.Lock()
	defer h.codeMutex.Unlock()

	now := time.Now()
	for code, authCode := range h.authCodes {
		if now.After(authCode.ExpiresAt) {
			delete(h.authCodes, code)
		}
	}
}

// GetAuthorizationCode retrieves an authorization code (for token endpoint)
func (h *Handle) GetAuthorizationCode(code string) (*AuthorizationCode, error) {
	h.codeMutex.RLock()
	defer h.codeMutex.RUnlock()

	authCode, exists := h.authCodes[code]
	if !exists {
		return nil, fmt.Errorf("authorization code not found")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	if authCode.Used {
		return nil, fmt.Errorf("authorization code already used")
	}

	return authCode, nil
}

// MarkAuthorizationCodeUsed marks an authorization code as used
func (h *Handle) MarkAuthorizationCodeUsed(code string) error {
	h.codeMutex.Lock()
	defer h.codeMutex.Unlock()

	authCode, exists := h.authCodes[code]
	if !exists {
		return fmt.Errorf("authorization code not found")
	}

	authCode.Used = true
	return nil
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

	slog.Info("Token request parameters",
		"grant_type", grantType,
		"client_id", clientID,
		"code", code,
		"redirect_uri", redirectURI)

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
	client, err := h.ClientService.ValidateClientCredentials(clientID, clientSecret)
	if err != nil {
		slog.Error("Invalid client credentials", "error", err, "client_id", clientID)
		h.writeErrorResponse(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return nil
	}

	// Get and validate authorization code
	authCode, err := h.GetAuthorizationCode(code)
	if err != nil {
		slog.Error("Invalid authorization code", "error", err, "code", code)
		h.writeErrorResponse(w, "invalid_grant", "Invalid or expired authorization code", http.StatusBadRequest)
		return nil
	}

	// Validate that the authorization code matches the client and redirect URI
	if authCode.ClientID != clientID {
		slog.Error("Authorization code client mismatch", "expected", authCode.ClientID, "provided", clientID)
		h.writeErrorResponse(w, "invalid_grant", "Authorization code was issued to a different client", http.StatusBadRequest)
		return nil
	}

	if authCode.RedirectURI != redirectURI {
		slog.Error("Authorization code redirect URI mismatch", "expected", authCode.RedirectURI, "provided", redirectURI)
		h.writeErrorResponse(w, "invalid_grant", "Redirect URI mismatch", http.StatusBadRequest)
		return nil
	}

	// Mark the authorization code as used
	if err := h.MarkAuthorizationCodeUsed(code); err != nil {
		slog.Error("Failed to mark authorization code as used", "error", err)
		h.writeErrorResponse(w, "server_error", "Internal server error", http.StatusInternalServerError)
		return nil
	}

	// Generate access token
	accessToken, err := h.generateAccessToken(authCode.UserID, client.ClientID, authCode.Scope)
	if err != nil {
		slog.Error("Failed to generate access token", "error", err)
		h.writeErrorResponse(w, "server_error", "Failed to generate access token", http.StatusInternalServerError)
		return nil
	}

	// Create token response
	tokenResponse := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // 1 hour
		Scope:       stringPtr(authCode.Scope),
	}

	slog.Info("Token exchange successful",
		"client_id", clientID,
		"user_id", authCode.UserID,
		"scope", authCode.Scope)

	h.writeJSONResponse(w, tokenResponse, http.StatusOK)
	return nil
}

// generateAccessToken creates a JWT access token for the user
func (h *Handle) generateAccessToken(userID, clientID, scope string) (string, error) {
	if h.JwtAuth == nil {
		return "", fmt.Errorf("JWT authenticator not initialized")
	}

	// Create claims for the access token
	claims := map[string]interface{}{
		"sub":       userID,                           // Subject (user ID)
		"aud":       clientID,                         // Audience (client ID)
		"iss":       "simple-idm",                     // Issuer
		"scope":     scope,                            // Granted scopes
		"token_use": "access",                         // Token usage type
		"exp":       time.Now().Add(time.Hour).Unix(), // Expires in 1 hour
		"iat":       time.Now().Unix(),                // Issued at
	}

	// Generate the JWT token
	_, tokenString, err := h.JwtAuth.Encode(claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode JWT token: %w", err)
	}

	return tokenString, nil
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
