package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/pkce"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Service Layer Types

// TokenRequestParams represents parameters for a token request
type TokenRequestParams struct {
	GrantType    string
	Code         string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// TokenResponse represents the response from a token request
type TokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	Scope        *string `json:"scope,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
}

// ErrorResponse represents an OAuth2 error response
type ErrorResponse struct {
	Error            string  `json:"error"`
	ErrorDescription *string `json:"error_description,omitempty"`
	ErrorURI         *string `json:"error_uri,omitempty"`
}

// UserInfoResponse represents OIDC user information response
type UserInfoResponse struct {
	Sub   string  `json:"sub"`             // Subject identifier (required)
	Name  *string `json:"name,omitempty"`  // Full name
	Email *string `json:"email,omitempty"` // Email address
}

// OIDCService provides OIDC business logic operations
type OIDCService struct {
	repository      OIDCRepository
	clientService   *oauth2client.ClientService
	tokenGenerator  tokengenerator.TokenGenerator
	userMapper      mapper.UserMapper
	codeExpiration  time.Duration
	tokenExpiration time.Duration
	baseURL         string
	loginURL        string
	issuer          string
}

// Option is a function that configures an OIDCService
type Option func(*OIDCService)

// WithCodeExpiration sets the authorization code expiration duration
func WithCodeExpiration(duration time.Duration) Option {
	return func(s *OIDCService) {
		s.codeExpiration = duration
	}
}

// WithTokenExpiration sets the access token expiration duration
func WithTokenExpiration(duration time.Duration) Option {
	return func(s *OIDCService) {
		s.tokenExpiration = duration
	}
}

// WithBaseURL sets the base URL for the OIDC service
func WithBaseURL(url string) Option {
	return func(s *OIDCService) {
		s.baseURL = url
	}
}

// WithLoginURL sets the login URL for redirecting unauthenticated users
func WithLoginURL(url string) Option {
	return func(s *OIDCService) {
		s.loginURL = url
	}
}

// WithTokenGenerator sets the token generator for creating and validating tokens
func WithTokenGenerator(generator tokengenerator.TokenGenerator) Option {
	return func(s *OIDCService) {
		s.tokenGenerator = generator
	}
}

// WithUserMapper sets the user mapper for fetching user data
func WithUserMapper(userMapper mapper.UserMapper) Option {
	return func(s *OIDCService) {
		s.userMapper = userMapper
	}
}

// WithIssuer sets the issuer URL for JWT tokens
func WithIssuer(issuer string) Option {
	return func(s *OIDCService) {
		s.issuer = issuer
	}
}

// OIDCServiceOptions contains optional parameters for creating an OIDCService (deprecated)
type OIDCServiceOptions struct {
	CodeExpiration  time.Duration
	TokenExpiration time.Duration
	BaseURL         string
	LoginURL        string
}

// NewOIDCServiceWithOptions creates a new OIDC service using functional options
func NewOIDCServiceWithOptions(repository OIDCRepository, clientService *oauth2client.ClientService, opts ...Option) *OIDCService {
	// Create service with default values
	service := &OIDCService{
		repository:      repository,
		clientService:   clientService,
		codeExpiration:  10 * time.Minute,
		tokenExpiration: time.Hour,
		issuer:          "simple-idm", // Default issuer for backward compatibility
	}

	// Apply all options
	for _, opt := range opts {
		opt(service)
	}

	return service
}

// GenerateAuthorizationCode creates a new authorization code
func (s *OIDCService) GenerateAuthorizationCode(ctx context.Context, clientID, redirectURI, scope string, state *string, userID string) (string, error) {
	return s.GenerateAuthorizationCodeWithPKCE(ctx, clientID, redirectURI, scope, state, userID, "", "")
}

// GenerateAuthorizationCodeWithPKCE creates a new authorization code with PKCE support
func (s *OIDCService) GenerateAuthorizationCodeWithPKCE(ctx context.Context, clientID, redirectURI, scope string, state *string, userID, codeChallenge, codeChallengeMethod string) (string, error) {
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

	// Create the authorization code
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               stateStr,
		UserID:              userID,
		ExpiresAt:           time.Now().UTC().Add(s.codeExpiration),
		Used:                false,
		CreatedAt:           time.Now().UTC(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	// Store the authorization code
	err := s.repository.StoreAuthorizationCode(ctx, authCode)
	if err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

func (s *OIDCService) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	// Validate the code
	if code == "" {
		return nil, fmt.Errorf("authorization code cannot be empty")
	}

	// Get the authorization code from the repository
	authCode, err := s.repository.GetAuthorizationCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve authorization code: %w", err)
	}

	return authCode, nil
}

// ValidateAndConsumeAuthorizationCode validates an authorization code and marks it as used
func (s *OIDCService) ValidateAndConsumeAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) (*AuthorizationCode, error) {
	return s.ValidateAndConsumeAuthorizationCodeWithPKCE(ctx, code, clientID, redirectURI, "")
}

// ValidateAndConsumeAuthorizationCodeWithPKCE validates an authorization code with PKCE support and marks it as used
func (s *OIDCService) ValidateAndConsumeAuthorizationCodeWithPKCE(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*AuthorizationCode, error) {
	// Get the authorization code
	authCode, err := s.repository.GetAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Validate that the authorization code matches the client and redirect URI
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("authorization code was issued to a different client")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect URI mismatch")
	}

	// Validate PKCE if code challenge is present
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, fmt.Errorf("code verifier is required for PKCE")
		}

		// Import pkce package for validation
		err = s.validatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod)
		if err != nil {
			return nil, fmt.Errorf("PKCE validation failed: %w", err)
		}
	}

	// Mark the authorization code as used
	err = s.repository.MarkAuthorizationCodeUsed(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to mark authorization code as used: %w", err)
	}

	return authCode, nil
}

// validatePKCE validates the PKCE code verifier against the stored challenge
func (s *OIDCService) validatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeVerifier == "" {
		return fmt.Errorf("code verifier cannot be empty")
	}
	if codeChallenge == "" {
		return fmt.Errorf("code challenge cannot be empty")
	}
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256" // Default to S256
	}

	// Use the PKCE package to validate the code verifier
	return pkce.ValidateCodeVerifier(codeVerifier, codeChallenge, pkce.ChallengeMethod(codeChallengeMethod))
}

// GenerateAccessToken creates a JWT access token for the user
func (s *OIDCService) GenerateAccessToken(ctx context.Context, userID, clientID, scope string) (string, error) {
	// Prepare root modifications for standard JWT claims
	rootModifications := map[string]interface{}{
		"aud": []string{clientID}, // Audience (client ID)
		"iss": s.issuer,           // Issuer (configurable)
	}

	// Prepare extra claims for OIDC-specific data
	extraClaims := map[string]interface{}{
		"scope":     scope,    // Granted scopes
		"token_use": "access", // Token usage type
		"user_id":   userID,   // User ID
		"client_id": clientID, // Client ID
	}

	tokenString, _, err := s.tokenGenerator.GenerateToken(userID, s.tokenExpiration, rootModifications, extraClaims)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token using TokenGenerator: %w", err)
	}
	slog.Info("Access token generated successfully", "userID", userID, "access_token", tokenString)
	return tokenString, nil
}

// func (s *OIDCService) GenerateRefreshToken(ctx context.Context, userID, clientID, scope string) (string, error) {
// 	// Prepare root modifications for standard JWT claims
// 	rootModifications := map[string]interface{}{
// 		"aud": clientID,     // Audience (client ID)
// 		"iss": "simple-idm", // Issuer
// 	}
// 	// Prepare extra claims for OIDC-specific data
// 	extraClaims := map[string]interface{}{
// 		"scope":     scope,     // Granted scopes
// 		"token_use": "refresh", // Token usage type
// 		"user_id":   userID,    // User ID
// 		"client_id": clientID,  // Client ID
// 	}
// 	tokenString, _, err := s.tokenGenerator.GenerateToken(userID, s.tokenExpiration, rootModifications, extraClaims)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate refresh token using TokenGenerator: %w", err)
// 	}
// 	return tokenString, nil
// }

// GenerateIDToken creates an OIDC ID token (JWT) for the user
func (s *OIDCService) GenerateIDToken(ctx context.Context, userID, clientID, scope string) (string, error) {
	if s.userMapper == nil {
		slog.Error("UserMapper not configured")
		return "", fmt.Errorf("user mapper not configured")
	}
	slog.Info("generating ID token", "userID", userID, "clientID", clientID, "scope", scope)
	// Prepare root modifications for standard JWT claims
	rootModifications := map[string]interface{}{
		"aud": []string{clientID}, // Audience (client ID)
		"iss": s.issuer,           // Issuer (configurable)
	}

	// Prepare extra claims for OIDC-specific data
	// extraClaims := map[string]interface{}{
	// 	"scope":     scope,    // Granted scopes
	// 	"token_use": "id",     // Token usage type
	// 	"user_id":   userID,   // User ID
	// 	"client_id": clientID, // Client ID
	// }

	// Fetch real user data if UserMapper is available
	if userUUID, err := uuid.Parse(userID); err == nil {
		if user, err := s.userMapper.GetUserByUserID(ctx, userUUID); err == nil {
			slog.Info("user info from user mapper", "user", user)
			// Add OIDC-specific claims based on scope using real user data
			if containsScope(scope, "profile") {
				if user.DisplayName != "" {
					rootModifications["username"] = user.DisplayName
				}
			}

			if containsScope(scope, "email") {
				if user.UserInfo.Email != "" {
					rootModifications["email"] = user.UserInfo.Email
				}
			}

			// Add phone number support (new feature)
			if containsScope(scope, "phone") {
				if user.UserInfo.PhoneNumber != "" {
					rootModifications["phone_number"] = user.UserInfo.PhoneNumber
				}
			}
		} else {
			// Log error but continue with empty values
			fmt.Printf("Warning: Failed to fetch user data for ID %s: %v\n", userID, err)
		}
	} else {
		// Log error but continue with empty values
		fmt.Printf("Warning: Failed to parse user ID as UUID: %s\n", userID)
	}

	tokenString, _, err := s.tokenGenerator.GenerateToken(userID, s.tokenExpiration, rootModifications, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate ID token using TokenGenerator: %w", err)
	}
	slog.Info("ID token generated successfully", "userID", userID, "id_token", tokenString)
	return tokenString, nil
}

func (s *OIDCService) ValidateUserToken(accessToken string) (map[string]interface{}, error) {
	// Verify the token and get the token object
	token, err := s.tokenGenerator.ParseToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from token: invalid claims type")
	}

	// Verify that required claims are present
	if claims["sub"] == nil || claims["sub"] == "" {
		return nil, fmt.Errorf("token missing required 'sub' claim")
	}

	return claims, nil
}

// BuildCallbackURL constructs the callback URL with authorization code
func (s *OIDCService) BuildCallbackURL(redirectURI, code string, state *string) (string, error) {
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

// GetLoginURL constructs the login URL with return parameter
func (s *OIDCService) BuildLoginRedirectURL(returnURL string) string {
	// Redirect to the frontend login page
	// The frontend will handle the login and redirect back to the OAuth2 flow
	return s.loginURL + "?redirect=" + url.QueryEscape(returnURL)
}

func (s *OIDCService) GetTokenExpiration() time.Duration {
	if s.tokenExpiration > 0 {
		return s.tokenExpiration
	}
	return time.Hour // Default to 1 hour if not set
}
func (s *OIDCService) GetCodeExpiration() time.Duration {
	if s.codeExpiration > 0 {
		return s.codeExpiration
	}
	return 10 * time.Minute // Default to 10 minutes if not set
}

func (s *OIDCService) GetBaseURL() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return "http://localhost:4000" // Default base URL
}

func (s *OIDCService) GetLoginURL() string {
	if s.loginURL != "" {
		return s.loginURL
	}
	return "http://localhost:3000/login" // Default login URL
}

// Request/Response DTOs for service layer

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               *string
	CodeChallenge       *string
	CodeChallengeMethod *string
	AccessToken         string // Extracted from HTTP request by handler
	RequestURL          string // Full request URL for building auth URL
}

// AuthorizationResponse represents the result of processing an authorization request
type AuthorizationResponse struct {
	Success     bool
	RedirectURL string
	ErrorCode   string
	ErrorDesc   string
	HTTPStatus  int
}

// TokenRequest represents an OAuth2 token exchange request
type TokenRequest struct {
	GrantType    string
	Code         string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	CodeVerifier string
}

// TokenExchangeResponse represents the result of a token exchange
type TokenExchangeResponse struct {
	Success     bool
	IDToken     string
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
	ErrorCode   string
	ErrorDesc   string
	HTTPStatus  int
}

// ProcessAuthorizationRequest handles the complete OAuth2 authorization flow
func (s *OIDCService) ProcessAuthorizationRequest(ctx context.Context, req AuthorizationRequest) *AuthorizationResponse {
	// 1. Validate client and request parameters
	client, err := s.clientService.ValidateAuthorizationRequest(
		req.ClientID,
		req.RedirectURI,
		req.ResponseType,
		req.Scope,
	)
	if err != nil {
		return &AuthorizationResponse{
			Success:    false,
			ErrorCode:  "invalid_request",
			ErrorDesc:  err.Error(),
			HTTPStatus: 400,
		}
	}

	// 2. Check if user is authenticated
	userClaims, err := s.ValidateUserToken(req.AccessToken)
	if err != nil {
		// Build the full authorization URL to redirect back to after login
		authURL := fmt.Sprintf("%s%s", s.GetBaseURL(), req.RequestURL)
		loginURL := s.BuildLoginRedirectURL(authURL)

		return &AuthorizationResponse{
			Success:     false,
			RedirectURL: loginURL,
			HTTPStatus:  302, // Found - redirect to login
		}
	}

	// 3. Extract user ID from claims
	userID, ok := userClaims["sub"].(string)
	if !ok || userID == "" {
		return &AuthorizationResponse{
			Success:    false,
			ErrorCode:  "invalid_token",
			ErrorDesc:  "Invalid or missing user ID in token",
			HTTPStatus: 401,
		}
	}

	// 4. Generate authorization code (with PKCE support if provided)
	var authCode string
	if req.CodeChallenge != nil && *req.CodeChallenge != "" {
		// PKCE flow
		codeChallenge := *req.CodeChallenge
		codeChallengeMethod := string(pkce.ChallengeS256) // Default to S256
		if req.CodeChallengeMethod != nil {
			codeChallengeMethod = string(*req.CodeChallengeMethod)
		}

		authCode, err = s.GenerateAuthorizationCodeWithPKCE(
			ctx, client.ClientID, req.RedirectURI, req.Scope, req.State, userID,
			codeChallenge, codeChallengeMethod)
	} else {
		// Standard flow (backward compatibility)
		authCode, err = s.GenerateAuthorizationCode(
			ctx, client.ClientID, req.RedirectURI, req.Scope, req.State, userID)
	}

	if err != nil {
		return &AuthorizationResponse{
			Success:    false,
			ErrorCode:  "server_error",
			ErrorDesc:  "Failed to generate authorization code",
			HTTPStatus: 400,
		}
	}

	// 5. Build callback URL and redirect
	callbackURL, err := s.BuildCallbackURL(req.RedirectURI, authCode, req.State)
	if err != nil {
		return &AuthorizationResponse{
			Success:    false,
			ErrorCode:  "server_error",
			ErrorDesc:  "Failed to build callback URL",
			HTTPStatus: 400,
		}
	}

	return &AuthorizationResponse{
		Success:     true,
		RedirectURL: callbackURL,
		HTTPStatus:  302, // Found - redirect to client
	}
}

// ProcessTokenRequest handles the complete OAuth2 token exchange flow
func (s *OIDCService) ProcessTokenRequest(ctx context.Context, req TokenRequest) *TokenExchangeResponse {
	// Validate grant type
	if req.GrantType != "authorization_code" {
		return &TokenExchangeResponse{
			Success:    false,
			ErrorCode:  "unsupported_grant_type",
			ErrorDesc:  "Only authorization_code grant type is supported",
			HTTPStatus: 400,
		}
	}

	// Validate required parameters
	if req.Code == "" || req.ClientID == "" || req.ClientSecret == "" || req.RedirectURI == "" {
		return &TokenExchangeResponse{
			Success:    false,
			ErrorCode:  "invalid_request",
			ErrorDesc:  "Missing required parameters",
			HTTPStatus: 400,
		}
	}

	// Validate client credentials
	client, err := s.clientService.ValidateClientCredentials(req.ClientID, req.ClientSecret)
	if err != nil {
		return &TokenExchangeResponse{
			Success:    false,
			ErrorCode:  "invalid_client",
			ErrorDesc:  "Invalid client credentials",
			HTTPStatus: 401,
		}
	}

	// Get and validate authorization code (with PKCE support if provided)
	var authCode *AuthorizationCode
	if req.CodeVerifier != "" {
		// PKCE flow - validate code verifier
		authCode, err = s.ValidateAndConsumeAuthorizationCodeWithPKCE(ctx, req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
	} else {
		// Standard flow (backward compatibility)
		authCode, err = s.ValidateAndConsumeAuthorizationCode(ctx, req.Code, req.ClientID, req.RedirectURI)
	}

	if err != nil {
		return &TokenExchangeResponse{
			Success:    false,
			ErrorCode:  "invalid_grant",
			ErrorDesc:  "Invalid or expired authorization code",
			HTTPStatus: 400,
		}
	}

	// Generate ID token
	idToken, err := s.GenerateIDToken(ctx, authCode.UserID, client.ClientID, authCode.Scope)
	if err != nil {
		return &TokenExchangeResponse{
			Success:    false,
			ErrorCode:  "server_error",
			ErrorDesc:  "Failed to generate ID token",
			HTTPStatus: 500,
		}
	}

	accessToken, err := s.GenerateAccessToken(ctx, authCode.UserID, client.ClientID, authCode.Scope)

	return &TokenExchangeResponse{
		Success:     true,
		IDToken:     idToken,
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // 1 hour
		Scope:       authCode.Scope,
		HTTPStatus:  200,
	}
}

// GetUserInfo validates an access token and returns user information
func (s *OIDCService) GetUserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	// Validate the access token
	claims, err := s.ValidateUserToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	// Extract user ID from claims
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("invalid or missing user ID in token")
	}

	// Extract scope from claims to determine what information to return
	scope := ""
	if scopeClaim, exists := claims["scope"]; exists {
		if scopeStr, ok := scopeClaim.(string); ok {
			scope = scopeStr
		}
	}

	// Build user info response based on available claims and scope
	userInfo := &UserInfoResponse{
		Sub: userID, // Subject is always required
	}

	// Add profile information if profile scope is granted
	if containsScope(scope, "profile") {
		// Try to extract name information from claims
		if extraClaims, exists := claims["extra_claims"]; exists {
			if extraMap, ok := extraClaims.(map[string]interface{}); ok {
				if name, exists := extraMap["display_name"]; exists {
					if nameStr, ok := name.(string); ok {
						userInfo.Name = &nameStr
					}
				}
			}
		}
	}

	// Add email information if email scope is granted
	if containsScope(scope, "email") {
		if extraMap, ok := claims["extra_claims"].(map[string]interface{}); ok {
			if userInfoMap, ok := extraMap["user_info"].(map[string]interface{}); ok {
				if emailStr, ok := userInfoMap["email"].(string); ok {
					userInfo.Email = &emailStr
				}
			}
		}
	}

	return userInfo, nil
}

// containsScope checks if a specific scope is present in the scope string
func containsScope(scopeString, targetScope string) bool {
	if scopeString == "" {
		return false
	}
	scopes := strings.Fields(scopeString)
	for _, scope := range scopes {
		if scope == targetScope {
			return true
		}
	}
	return false
}
