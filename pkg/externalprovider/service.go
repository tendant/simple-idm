package externalprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notification"
)

// ExternalProviderService handles OAuth2 client flows with external identity providers
type ExternalProviderService struct {
	repository          ExternalProviderRepository
	loginService        *login.LoginService
	userMapper          mapper.UserMapper
	notificationManager *notification.NotificationManager
	baseURL             string
	stateExpiration     time.Duration
	httpClient          *http.Client
	autoUserCreation    bool
	userCreationEnabled bool
}

// Option is a function that configures an ExternalProviderService
type Option func(*ExternalProviderService)

// WithBaseURL sets the base URL for the external provider service
func WithBaseURL(baseURL string) Option {
	return func(s *ExternalProviderService) {
		s.baseURL = baseURL
	}
}

// WithStateExpiration sets the state expiration duration for OAuth2 flows
func WithStateExpiration(duration time.Duration) Option {
	return func(s *ExternalProviderService) {
		s.stateExpiration = duration
	}
}

// WithHTTPClient sets the HTTP client for external API calls
func WithHTTPClient(client *http.Client) Option {
	return func(s *ExternalProviderService) {
		s.httpClient = client
	}
}

// WithNotificationManager sets the notification manager for sending emails
func WithNotificationManager(nm *notification.NotificationManager) Option {
	return func(s *ExternalProviderService) {
		s.notificationManager = nm
	}
}

// WithAutoUserCreation enables or disables automatic user creation for new external users
func WithAutoUserCreation(enabled bool) Option {
	return func(s *ExternalProviderService) {
		s.autoUserCreation = enabled
	}
}

// WithUserCreationEnabled enables or disables user creation functionality
func WithUserCreationEnabled(enabled bool) Option {
	return func(s *ExternalProviderService) {
		s.userCreationEnabled = enabled
	}
}

// NewExternalProviderService creates a new external provider service with functional options
func NewExternalProviderService(
	repository ExternalProviderRepository,
	loginService *login.LoginService,
	userMapper mapper.UserMapper,
	opts ...Option,
) *ExternalProviderService {
	// Create service with default values
	service := &ExternalProviderService{
		repository:          repository,
		loginService:        loginService,
		userMapper:          userMapper,
		baseURL:             "http://localhost:4000",
		stateExpiration:     10 * time.Minute,
		httpClient:          &http.Client{Timeout: 30 * time.Second},
		autoUserCreation:    false, // Security by default - don't auto-create users
		userCreationEnabled: false, // Security by default - don't allow user creation
	}

	// Apply all options
	for _, opt := range opts {
		opt(service)
	}

	return service
}

// ExternalProviderServiceOptions contains optional configuration for the service (deprecated)
// This struct is kept for backward compatibility but should be replaced with functional options
type ExternalProviderServiceOptions struct {
	BaseURL         string
	StateExpiration time.Duration
	HTTPClient      *http.Client
}

// InitiateOAuth2Flow starts the OAuth2 authorization flow for a given provider
func (s *ExternalProviderService) InitiateOAuth2Flow(ctx context.Context, providerID, redirectURL string) (string, error) {
	// Get the provider configuration
	provider, err := s.repository.GetProvider(providerID)
	if err != nil {
		return "", fmt.Errorf("failed to get provider: %w", err)
	}

	if !provider.Enabled {
		return "", fmt.Errorf("provider is disabled: %s", providerID)
	}

	// Generate a secure state parameter
	state, err := s.generateSecureState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Store the state for later validation
	oauth2State := &OAuth2State{
		State:       state,
		Provider:    providerID,
		RedirectURL: redirectURL,
		ExpiresAt:   time.Now().Add(s.stateExpiration).Unix(),
	}

	if err := s.repository.StoreState(oauth2State); err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}

	// Build the callback URL
	callbackURL := fmt.Sprintf("%s/api/idm/external/%s/callback", s.baseURL, providerID)

	// Build the authorization URL
	authURL, err := provider.BuildAuthURL(state, callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to build auth URL: %w", err)
	}

	slog.Info("OAuth2 flow initiated", "provider", providerID, "state", state, "auth_url", authURL)
	return authURL, nil
}

// HandleOAuth2Callback processes the OAuth2 callback from the external provider
func (s *ExternalProviderService) HandleOAuth2Callback(ctx context.Context, providerID, code, state string) (*login.LoginResult, error) {
	// Validate the state parameter
	oauth2State, err := s.repository.GetState(state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state: %w", err)
	}

	// Verify the provider matches
	if oauth2State.Provider != providerID {
		return nil, fmt.Errorf("provider mismatch: expected %s, got %s", oauth2State.Provider, providerID)
	}

	// Clean up the state (single use)
	if err := s.repository.DeleteState(state); err != nil {
		slog.Warn("Failed to delete state", "state", state, "error", err)
	}

	// Get the provider configuration
	provider, err := s.repository.GetProvider(providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// Exchange the authorization code for an access token
	tokenResponse, err := s.exchangeCodeForToken(provider, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user information from the provider
	userInfo, err := s.getUserInfo(provider, tokenResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Find or create user account
	loginResult, err := s.findOrCreateUser(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	slog.Info("OAuth2 callback processed successfully",
		"provider", providerID,
		"external_id", userInfo.ExternalID,
		"email", userInfo.Email,
		"login_id", loginResult.LoginID)

	return loginResult, nil
}

// GetEnabledProviders returns all enabled external providers
func (s *ExternalProviderService) GetEnabledProviders(ctx context.Context) (map[string]*ExternalProvider, error) {
	return s.repository.GetEnabledProviders()
}

// generateSecureState generates a cryptographically secure random state parameter
func (s *ExternalProviderService) generateSecureState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// exchangeCodeForToken exchanges an authorization code for an access token
func (s *ExternalProviderService) exchangeCodeForToken(provider *ExternalProvider, code string) (*TokenResponse, error) {
	callbackURL := fmt.Sprintf("%s/api/idm/external/%s/callback", s.baseURL, provider.ID)

	// Prepare the token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", callbackURL)

	// Create the HTTP request
	req, err := http.NewRequest("POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Make the request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make token request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the token response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	slog.Info("Token exchange successful", "provider", provider.ID, "token_type", tokenResponse.TokenType)
	return &tokenResponse, nil
}

// getUserInfo retrieves user information from the provider's API
func (s *ExternalProviderService) getUserInfo(provider *ExternalProvider, accessToken string) (*ExternalUserInfo, error) {
	// Create the HTTP request
	req, err := http.NewRequest("GET", provider.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	// Make the request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make user info request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the user info based on the provider
	userInfo, err := s.parseUserInfo(provider, body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	slog.Info("User info retrieved", "provider", provider.ID, "external_id", userInfo.ExternalID, "email", userInfo.Email)
	return userInfo, nil
}

// parseUserInfo parses user information from different providers
func (s *ExternalProviderService) parseUserInfo(provider *ExternalProvider, data []byte) (*ExternalUserInfo, error) {
	var rawUserInfo map[string]interface{}
	if err := json.Unmarshal(data, &rawUserInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	userInfo := &ExternalUserInfo{
		ProviderID: provider.ID,
	}

	// Parse user info based on provider type
	switch provider.ID {
	case "google":
		userInfo.ExternalID = getStringValue(rawUserInfo, "id")
		userInfo.Email = getStringValue(rawUserInfo, "email")
		userInfo.EmailVerified = getBoolValue(rawUserInfo, "verified_email")
		userInfo.Name = getStringValue(rawUserInfo, "name")
		userInfo.FirstName = getStringValue(rawUserInfo, "given_name")
		userInfo.LastName = getStringValue(rawUserInfo, "family_name")
		userInfo.Picture = getStringValue(rawUserInfo, "picture")
		userInfo.Locale = getStringValue(rawUserInfo, "locale")

	case "microsoft":
		userInfo.ExternalID = getStringValue(rawUserInfo, "id")
		userInfo.Email = getStringValue(rawUserInfo, "mail")
		if userInfo.Email == "" {
			userInfo.Email = getStringValue(rawUserInfo, "userPrincipalName")
		}
		userInfo.EmailVerified = true // Microsoft emails are typically verified
		userInfo.Name = getStringValue(rawUserInfo, "displayName")
		userInfo.FirstName = getStringValue(rawUserInfo, "givenName")
		userInfo.LastName = getStringValue(rawUserInfo, "surname")

	case "github":
		userInfo.ExternalID = fmt.Sprintf("%v", rawUserInfo["id"])
		userInfo.Email = getStringValue(rawUserInfo, "email")
		userInfo.EmailVerified = true // GitHub emails are verified
		userInfo.Name = getStringValue(rawUserInfo, "name")
		if userInfo.Name == "" {
			userInfo.Name = getStringValue(rawUserInfo, "login")
		}
		userInfo.Picture = getStringValue(rawUserInfo, "avatar_url")

	default:
		// Generic OIDC parsing
		userInfo.ExternalID = getStringValue(rawUserInfo, "sub")
		if userInfo.ExternalID == "" {
			userInfo.ExternalID = getStringValue(rawUserInfo, "id")
		}
		userInfo.Email = getStringValue(rawUserInfo, "email")
		userInfo.EmailVerified = getBoolValue(rawUserInfo, "email_verified")
		userInfo.Name = getStringValue(rawUserInfo, "name")
		userInfo.FirstName = getStringValue(rawUserInfo, "given_name")
		userInfo.LastName = getStringValue(rawUserInfo, "family_name")
		userInfo.Picture = getStringValue(rawUserInfo, "picture")
		userInfo.Locale = getStringValue(rawUserInfo, "locale")
	}

	if userInfo.ExternalID == "" {
		return nil, fmt.Errorf("no external ID found in user info")
	}

	if userInfo.Email == "" {
		return nil, fmt.Errorf("no email found in user info")
	}

	return userInfo, nil
}

// findOrCreateUser finds an existing user by email or creates a new one
func (s *ExternalProviderService) findOrCreateUser(ctx context.Context, userInfo *ExternalUserInfo) (*login.LoginResult, error) {
	// Try to find existing user by email
	loginResult, err := s.loginService.LoginByEmail(ctx, userInfo.Email, "")
	if err == nil {
		// User found, return successful login
		slog.Info("Existing user found for external login", "email", userInfo.Email, "provider", userInfo.ProviderID)
		return &loginResult, nil
	}

	// User not found, create a new account
	slog.Info("Creating new user for external login", "email", userInfo.Email, "provider", userInfo.ProviderID)

	// For now, we'll return an error indicating that user creation is not implemented
	// In a full implementation, you would create a new user account here
	return nil, fmt.Errorf("user not found and automatic user creation is not implemented yet. Email: %s", userInfo.Email)
}

// Helper functions for parsing user info
func getStringValue(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolValue(data map[string]interface{}, key string) bool {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// CleanupExpiredStates removes expired OAuth2 states
func (s *ExternalProviderService) CleanupExpiredStates(ctx context.Context) error {
	return s.repository.CleanupExpiredStates()
}
