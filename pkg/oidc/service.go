package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// OIDCService provides OIDC business logic operations
type OIDCService struct {
	repository      OIDCRepository
	clientService   *oauth2client.ClientService
	tokenGenerator  tokengenerator.TokenGenerator
	codeExpiration  time.Duration
	tokenExpiration time.Duration
	baseURL         string
	loginURL        string
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
		"aud": clientID,     // Audience (client ID)
		"iss": "simple-idm", // Issuer
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

	return tokenString, nil
}

func (s *OIDCService) GenerateRefreshToken(ctx context.Context, userID, clientID, scope string) (string, error) {
	// Prepare root modifications for standard JWT claims
	rootModifications := map[string]interface{}{
		"aud": clientID,     // Audience (client ID)
		"iss": "simple-idm", // Issuer
	}
	// Prepare extra claims for OIDC-specific data
	extraClaims := map[string]interface{}{
		"scope":     scope,     // Granted scopes
		"token_use": "refresh", // Token usage type
		"user_id":   userID,    // User ID
		"client_id": clientID,  // Client ID
	}
	tokenString, _, err := s.tokenGenerator.GenerateToken(userID, s.tokenExpiration, rootModifications, extraClaims)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token using TokenGenerator: %w", err)
	}
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
