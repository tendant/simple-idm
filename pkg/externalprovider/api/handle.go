package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm/pkg/externalprovider"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Handle implements the ServerInterface for external provider endpoints
type Handle struct {
	externalProviderService *externalprovider.ExternalProviderService
	loginService            *login.LoginService
	tokenService            tokengenerator.TokenService
	tokenCookieService      tokengenerator.TokenCookieService
	frontendURL             string
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

		// Redirect to frontend with error
		redirectURL := fmt.Sprintf("%s/login?error=authentication_failed&error_description=%s", h.frontendURL, err.Error())
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
