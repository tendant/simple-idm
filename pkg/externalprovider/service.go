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

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/logins"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/role"
)

// ExternalProviderService handles OAuth2 client flows with external identity providers
type ExternalProviderService struct {
	repository          ExternalProviderRepository
	loginService        *login.LoginService
	userMapper          mapper.UserMapper
	notificationManager *notification.NotificationManager
	iamService          *iam.IamService
	roleService         *role.RoleService
	loginsService       *logins.LoginsService
	baseURL             string
	stateExpiration     time.Duration
	httpClient          *http.Client
	autoUserCreation    bool
	userCreationEnabled bool
	defaultRole         string
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

// WithIamService sets the IAM service for user creation
func WithIamService(iamService *iam.IamService) Option {
	return func(s *ExternalProviderService) {
		s.iamService = iamService
	}
}

// WithRoleService sets the role service for user role assignment
func WithRoleService(roleService *role.RoleService) Option {
	return func(s *ExternalProviderService) {
		s.roleService = roleService
	}
}

// WithLoginsService sets the logins service for login account creation
func WithLoginsService(loginsService *logins.LoginsService) Option {
	return func(s *ExternalProviderService) {
		s.loginsService = loginsService
	}
}

// WithDefaultRole sets the default role for new users
func WithDefaultRole(role string) Option {
	return func(s *ExternalProviderService) {
		s.defaultRole = role
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

	// User not found, check if user creation is enabled
	if !s.userCreationEnabled {
		slog.Warn("User creation is disabled", "email", userInfo.Email, "provider", userInfo.ProviderID)
		return nil, fmt.Errorf("user not found and user creation is disabled. Email: %s", userInfo.Email)
	}

	if !s.autoUserCreation {
		slog.Warn("Automatic user creation is disabled", "email", userInfo.Email, "provider", userInfo.ProviderID)
		return nil, fmt.Errorf("user not found and automatic user creation is disabled. Email: %s", userInfo.Email)
	}

	// Check if required services are available
	if s.loginsService == nil {
		return nil, fmt.Errorf("logins service not configured for user creation")
	}
	if s.iamService == nil {
		return nil, fmt.Errorf("IAM service not configured for user creation")
	}
	if s.roleService == nil {
		return nil, fmt.Errorf("role service not configured for user creation")
	}

	// Create a new user account
	slog.Info("Creating new user for external login", "email", userInfo.Email, "provider", userInfo.ProviderID)

	// Step 1: Create login account (passwordless for external provider users)
	username := userInfo.Email // Use email as username
	loginAccount, err := s.loginsService.CreateLoginWithoutPassword(ctx, username, fmt.Sprintf("external:%s", userInfo.ProviderID))
	if err != nil {
		slog.Error("Failed to create login account", "error", err, "email", userInfo.Email)
		return nil, fmt.Errorf("failed to create login account: %w", err)
	}

	// Step 2: Set passwordless flag
	loginID, err := uuid.Parse(loginAccount.ID)
	if err != nil {
		slog.Error("Failed to parse login ID", "error", err, "login_id", loginAccount.ID)
		// Continue anyway, as the user is created
	} else {
		err = s.loginService.GetRepository().SetPasswordlessFlag(ctx, loginID, true)
		if err != nil {
			slog.Error("Failed to set passwordless flag", "error", err, "login_id", loginID)
			// Continue anyway, as the user is created
		}
	}

	// Step 3: Determine user's display name
	displayName := userInfo.Name
	if displayName == "" && userInfo.FirstName != "" {
		displayName = userInfo.FirstName
		if userInfo.LastName != "" {
			displayName = userInfo.FirstName + " " + userInfo.LastName
		}
	}
	if displayName == "" {
		displayName = userInfo.Email // Fallback to email
	}

	// Step 4: Create user profile
	user, err := s.iamService.CreateUser(ctx, userInfo.Email, username, displayName, []uuid.UUID{}, loginAccount.ID)
	if err != nil {
		slog.Error("Failed to create user profile", "error", err, "email", userInfo.Email)
		// TODO: Consider rollback of login account creation
		return nil, fmt.Errorf("failed to create user profile: %w", err)
	}

	// Step 5: Assign default role if specified
	if s.defaultRole != "" {
		roleID, err := s.roleService.GetRoleIdByName(ctx, s.defaultRole)
		if err != nil {
			slog.Error("Failed to get default role ID", "error", err, "role", s.defaultRole)
			// Continue without role assignment rather than failing the entire process
		} else {
			err = s.roleService.AddUserToRole(ctx, roleID, user.User.ID, username)
			if err != nil {
				slog.Error("Failed to assign default role", "error", err, "role", s.defaultRole, "user_id", user.User.ID)
				// Continue without role assignment rather than failing the entire process
			} else {
				slog.Info("Assigned default role to new user", "role", s.defaultRole, "user_id", user.User.ID, "email", userInfo.Email)
			}
		}
	}

	// Step 6: Send welcome notification (optional)
	if s.notificationManager != nil {
		// TODO: Implement welcome email notification
		slog.Info("Welcome notification would be sent here", "email", userInfo.Email, "provider", userInfo.ProviderID)
	}

	// Step 7: Return successful login result
	// Get users associated with this login ID using the UserMapper
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		slog.Error("Failed to get users by login ID after creation", "error", err, "login_id", loginID)
		return nil, fmt.Errorf("failed to get user information after creation: %w", err)
	}

	loginResult = login.LoginResult{
		Users:   users,
		LoginID: loginID,
		Success: true,
	}

	slog.Info("Successfully created new user for external login",
		"email", userInfo.Email,
		"provider", userInfo.ProviderID,
		"login_id", loginID,
		"user_id", user.User.ID,
		"display_name", displayName)

	return &loginResult, nil
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
