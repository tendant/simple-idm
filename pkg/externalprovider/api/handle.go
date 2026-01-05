package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tendant/simple-idm/pkg/externalprovider"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

// TokenVerifier is a function that verifies an ID token and returns user info
type TokenVerifier func(ctx context.Context, providerID, idToken string) (*externalprovider.ExternalUserInfo, error)

// Handle implements the ServerInterface for external provider endpoints
type Handle struct {
	externalProviderService *externalprovider.ExternalProviderService
	loginService            *login.LoginService
	tokenService            tokengenerator.TokenService
	tokenCookieService      tokengenerator.TokenCookieService
	frontendURL             string
	tokenVerifiers          map[string]TokenVerifier // provider -> verifier function
	validClientIDs          map[string][]string      // provider -> list of valid client IDs
}

// NewHandle creates a new external provider API handler
func NewHandle(
	externalProviderService *externalprovider.ExternalProviderService,
	loginService *login.LoginService,
	tokenService tokengenerator.TokenService,
	tokenCookieService tokengenerator.TokenCookieService,
) *Handle {
	return &Handle{
		externalProviderService: externalProviderService,
		loginService:            loginService,
		tokenService:            tokenService,
		tokenCookieService:      tokenCookieService,
		frontendURL:             "http://localhost:3000",
		tokenVerifiers:          make(map[string]TokenVerifier),
		validClientIDs:          make(map[string][]string),
	}
}

// WithFrontendURL sets the frontend URL for redirects
func (h *Handle) WithFrontendURL(url string) *Handle {
	h.frontendURL = url
	return h
}

// ListProviders implements ServerInterface.ListProviders
func (h *Handle) ListProviders(w http.ResponseWriter, r *http.Request) *Response {
	ctx := r.Context()

	providers, err := h.externalProviderService.GetEnabledProviders(ctx)
	if err != nil {
		slog.Error("Failed to get enabled providers", "error", err)
		return ListProvidersJSON500Response(Error{
			Error:            "internal_error",
			ErrorDescription: "Failed to retrieve providers",
		})
	}

	// Convert to response format (remove sensitive information)
	providerList := make([]ExternalProvider, 0, len(providers))
	for _, provider := range providers {
		providerList = append(providerList, ExternalProvider{
			ID:          provider.ID,
			Name:        provider.Name,
			DisplayName: provider.DisplayName,
			Enabled:     provider.Enabled,
			IconURL:     &provider.IconURL,
			Description: &provider.Description,
		})
	}

	return ListProvidersJSON200Response(struct {
		Providers []ExternalProvider `json:"providers,omitempty"`
	}{
		Providers: providerList,
	})
}

// InitiateOAuth2flow implements ServerInterface.InitiateOAuth2flow
func (h *Handle) InitiateOAuth2flow(w http.ResponseWriter, r *http.Request, provider InitiateOAuth2flowParamsProvider, params InitiateOAuth2flowParams) *Response {
	ctx := r.Context()
	providerID := string(provider)

	if providerID == "" {
		return InitiateOAuth2flowJSON400Response(Error{
			Error:            "invalid_request",
			ErrorDescription: "Provider ID is required",
		})
	}

	// Get redirect URL from query parameter
	redirectURL := h.frontendURL
	if params.RedirectURL != nil && *params.RedirectURL != "" {
		redirectURL = *params.RedirectURL
	}

	// Initiate OAuth2 flow
	authURL, err := h.externalProviderService.InitiateOAuth2Flow(ctx, providerID, redirectURL)
	if err != nil {
		slog.Error("Failed to initiate OAuth2 flow", "provider", providerID, "error", err)

		// Check if it's a provider not found error
		if err.Error() == fmt.Sprintf("failed to get provider: provider not found: %s", providerID) {
			return InitiateOAuth2flowJSON404Response(Error{
				Error:            "provider_not_found",
				ErrorDescription: "Provider not found or disabled",
			})
		}

		return InitiateOAuth2flowJSON500Response(Error{
			Error:            "internal_error",
			ErrorDescription: "Failed to initiate authentication",
		})
	}

	slog.Info("Redirecting to external provider", "provider", providerID, "auth_url", authURL)

	// Redirect to the external provider
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// HandleOAuth2callback implements ServerInterface.HandleOAuth2callback
func (h *Handle) HandleOAuth2callback(w http.ResponseWriter, r *http.Request, provider HandleOAuth2callbackParamsProvider, params HandleOAuth2callbackParams) *Response {
	ctx := r.Context()
	providerID := string(provider)

	if providerID == "" {
		return HandleOAuth2callbackJSON400Response(Error{
			Error:            "invalid_request",
			ErrorDescription: "Provider ID is required",
		})
	}

	// Check for error parameters first
	if params.Error != nil && *params.Error != "" {
		errorDescription := "Authentication was denied or failed"
		if params.ErrorDescription != nil && *params.ErrorDescription != "" {
			errorDescription = *params.ErrorDescription
		}

		slog.Warn("OAuth2 callback received error", "provider", providerID, "error", *params.Error, "description", errorDescription)

		// Redirect to frontend with error
		redirectURL := fmt.Sprintf("%s/login?error=%s&error_description=%s", h.frontendURL, *params.Error, errorDescription)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return nil
	}

	if params.Code == "" {
		return HandleOAuth2callbackJSON400Response(Error{
			Error:            "invalid_request",
			ErrorDescription: "Authorization code is required",
		})
	}

	if params.State == "" {
		return HandleOAuth2callbackJSON400Response(Error{
			Error:            "invalid_request",
			ErrorDescription: "State parameter is required",
		})
	}

	// Handle the OAuth2 callback
	loginResult, err := h.externalProviderService.HandleOAuth2Callback(ctx, providerID, params.Code, params.State)
	if err != nil {
		slog.Error("Failed to handle OAuth2 callback", "provider", providerID, "error", err)

		// Check if this is a database/internal error and provide generic message
		var errorDescription string
		if isDatabaseError(err) {
			errorDescription = "An internal error occurred. Please try again later."
		} else {
			errorDescription = err.Error()
		}

		// Redirect to frontend with error
		redirectURL := fmt.Sprintf("%s/login?error=authentication_failed&error_description=%s", h.frontendURL, errorDescription)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return nil
	}

	if !loginResult.Success {
		slog.Error("OAuth2 callback login failed", "provider", providerID, "failure_reason", loginResult.FailureReason)

		// Redirect to frontend with error
		redirectURL := fmt.Sprintf("%s/login?error=login_failed&error_description=%s", h.frontendURL, loginResult.FailureReason)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return nil
	}

	// Generate JWT tokens for successful authentication
	if len(loginResult.Users) == 0 {
		slog.Error("No users found in login result", "provider", providerID)
		redirectURL := fmt.Sprintf("%s/login?error=no_user&error_description=No user information found", h.frontendURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return nil
	}

	user := loginResult.Users[0] // Use the first user

	// Convert user to token claims
	rootModifications, extraClaims := h.loginService.ToTokenClaims(user)

	// Generate tokens
	tokens, err := h.tokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate tokens", "error", err)
		redirectURL := fmt.Sprintf("%s/login?error=token_generation_failed&error_description=Failed to generate authentication tokens", h.frontendURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return nil
	}

	// Set authentication cookies
	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set authentication cookies", "error", err)
		redirectURL := fmt.Sprintf("%s/login?error=cookie_failed&error_description=Failed to set authentication cookies", h.frontendURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return nil
	}

	slog.Info("OAuth2 authentication successful",
		"provider", providerID,
		"user_id", user.UserId,
		"login_id", loginResult.LoginID)

	// Redirect to frontend with success
	redirectURL := fmt.Sprintf("%s/?auth=success", h.frontendURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// HealthCheck provides a simple health check endpoint
func (h *Handle) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok", "service": "external-provider-api"}`))
}

// WithGoogleTokenAuth configures Google ID token authentication for mobile apps
// clientIDs should include both web and mobile client IDs
func (h *Handle) WithGoogleTokenAuth(clientIDs ...string) *Handle {
	h.validClientIDs["google"] = clientIDs
	h.tokenVerifiers["google"] = h.verifyGoogleIDToken
	slog.Info("Google token auth configured", "client_ids", clientIDs)
	return h
}

// GoogleTokenInfo represents the response from Google's tokeninfo endpoint
type GoogleTokenInfo struct {
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Iat           string `json:"iat"`
	Exp           string `json:"exp"`
	Error         string `json:"error"`
	ErrorDesc     string `json:"error_description"`
}

// verifyGoogleIDToken verifies a Google ID token and returns user info
func (h *Handle) verifyGoogleIDToken(ctx context.Context, providerID, idToken string) (*externalprovider.ExternalUserInfo, error) {
	slog.Info("Verifying Google ID token", "token_length", len(idToken))

	// Use Google's tokeninfo endpoint to verify the token
	url := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	slog.Debug("Google tokeninfo response", "status", resp.StatusCode, "body", string(body))

	var tokenInfo GoogleTokenInfo
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for error in response
	if tokenInfo.Error != "" {
		return nil, fmt.Errorf("token verification failed: %s - %s", tokenInfo.Error, tokenInfo.ErrorDesc)
	}

	// Verify the audience matches one of our client IDs
	validClientIDs := h.validClientIDs["google"]
	slog.Info("Verifying token audience", "aud", tokenInfo.Aud, "azp", tokenInfo.Azp, "valid_client_ids", validClientIDs)

	isValidAudience := false
	for _, clientID := range validClientIDs {
		// Check both aud and azp - for mobile tokens, azp contains the mobile client ID
		if tokenInfo.Aud == clientID || tokenInfo.Azp == clientID {
			isValidAudience = true
			break
		}
	}

	if !isValidAudience {
		return nil, fmt.Errorf("invalid token audience: aud=%s, azp=%s not in allowed client IDs", tokenInfo.Aud, tokenInfo.Azp)
	}

	// Verify the issuer
	if tokenInfo.Iss != "https://accounts.google.com" && tokenInfo.Iss != "accounts.google.com" {
		return nil, fmt.Errorf("invalid token issuer: %s", tokenInfo.Iss)
	}

	slog.Info("Google ID token verified", "email", tokenInfo.Email, "sub", tokenInfo.Sub)

	return &externalprovider.ExternalUserInfo{
		ProviderID:    "google",
		ExternalID:    tokenInfo.Sub,
		Email:         tokenInfo.Email,
		EmailVerified: tokenInfo.EmailVerified == "true",
		Name:          tokenInfo.Name,
		FirstName:     tokenInfo.GivenName,
		LastName:      tokenInfo.FamilyName,
		Picture:       tokenInfo.Picture,
	}, nil
}

// TokenAuthRequest represents the request body for token authentication
type TokenAuthRequest struct {
	IDToken string `json:"id_token"`
}

// TokenAuthResponse represents the response for token authentication
type TokenAuthResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
}

// HandleTokenAuth handles authentication using a provider's ID token
// This endpoint is used by mobile apps that handle sign-in natively
// POST /{provider}/token
// Request body: { "id_token": "..." }
func (h *Handle) HandleTokenAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerID := chi.URLParam(r, "provider")

	slog.Info("HandleTokenAuth: Received request", "provider", providerID, "remote_addr", r.RemoteAddr)

	if providerID == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Provider ID is required")
		return
	}

	// Check if we have a token verifier for this provider
	verifier, ok := h.tokenVerifiers[providerID]
	if !ok {
		slog.Warn("No token verifier configured for provider", "provider", providerID)
		h.writeError(w, http.StatusBadRequest, "unsupported_provider", fmt.Sprintf("Token authentication not supported for provider: %s", providerID))
		return
	}

	// Parse request body
	var req TokenAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.IDToken == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "ID token is required")
		return
	}

	slog.Info("HandleTokenAuth: Verifying ID token", "provider", providerID, "token_length", len(req.IDToken))

	// Verify the token and get user info
	userInfo, err := verifier(ctx, providerID, req.IDToken)
	if err != nil {
		slog.Error("Token verification failed", "provider", providerID, "error", err)
		h.writeError(w, http.StatusUnauthorized, "token_verification_failed", err.Error())
		return
	}

	slog.Info("HandleTokenAuth: Token verified", "provider", providerID, "email", userInfo.Email)

	// Authenticate using the external provider service
	loginResult, err := h.externalProviderService.AuthenticateWithIDToken(ctx, userInfo)
	if err != nil {
		slog.Error("Authentication failed", "provider", providerID, "error", err)

		// Check if this is a database/internal error
		if isDatabaseError(err) {
			h.writeError(w, http.StatusInternalServerError, "internal_error", "An internal error occurred. Please try again later.")
			return
		}

		// Otherwise treat as authentication failure
		h.writeError(w, http.StatusUnauthorized, "auth_failed", err.Error())
		return
	}

	if !loginResult.Success || len(loginResult.Users) == 0 {
		slog.Error("Authentication returned no users", "provider", providerID)
		h.writeError(w, http.StatusUnauthorized, "auth_failed", "Authentication failed: no user returned")
		return
	}

	user := loginResult.Users[0]
	slog.Info("HandleTokenAuth: User authenticated", "provider", providerID, "user_id", user.UserId, "email", user.UserInfo.Email)

	// Generate tokens
	rootModifications, extraClaims := h.loginService.ToTokenClaims(user)
	tokens, err := h.tokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate tokens", "error", err)
		h.writeError(w, http.StatusInternalServerError, "token_generation_failed", "Failed to generate authentication tokens")
		return
	}

	// Set authentication cookies
	if err := h.tokenCookieService.SetTokensCookie(w, tokens); err != nil {
		slog.Warn("Failed to set authentication cookies", "error", err)
		// Continue - mobile apps may not use cookies
	}

	// Return response
	response := TokenAuthResponse{
		Authenticated: true,
		UserID:        user.UserId,
		Email:         user.UserInfo.Email,
		DisplayName:   user.DisplayName,
		AccessToken:   tokens["access_token"].Token,
		RefreshToken:  tokens["refresh_token"].Token,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	slog.Info("HandleTokenAuth: Success", "provider", providerID, "user_id", user.UserId)
}

// writeError writes a JSON error response
// isDatabaseError checks if an error is a database/internal error that should return 500
func isDatabaseError(err error) bool {
	if err == nil {
		return false
	}

	// Check for PostgreSQL errors using proper type checking
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Common PostgreSQL error codes that indicate server-side issues:
		// 42P01 - undefined_table
		// 42703 - undefined_column
		// 42883 - undefined_function
		// 53xxx - insufficient resources
		// 08xxx - connection exception
		// 57xxx - operator intervention
		// XX000 - internal error
		switch pgErr.Code {
		case "42P01", "42703", "42883": // Schema/structure errors
			return true
		}
		if len(pgErr.Code) >= 2 {
			prefix := pgErr.Code[:2]
			if prefix == "08" || prefix == "53" || prefix == "57" || prefix == "XX" {
				return true
			}
		}
	}

	return false
}

func (h *Handle) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":             code,
		"error_description": message,
	})
}

// HandlerWithTokenAuth creates an HTTP handler that includes both the generated routes
// and the custom token authentication endpoint
func HandlerWithTokenAuth(h *Handle, opts ...ServerOption) http.Handler {
	// Get the base handler with generated routes
	baseHandler := Handler(h, opts...)

	// Create a new router that wraps the base handler
	r := chi.NewRouter()

	// Add the token authentication endpoint FIRST (before the catch-all)
	r.Post("/{provider}/token", h.HandleTokenAuth)

	// Mount the base handler for all other routes
	r.Mount("/", baseHandler)

	return r
}
