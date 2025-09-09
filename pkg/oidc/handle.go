package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"golang.org/x/crypto/bcrypt"
)

// Config holds all configuration options for the OIDC provider
type Config struct {
	// PrivateKeyPath is the path to the RSA private key used for signing ID tokens
	PrivateKeyPath string

	// ClientID is the OAuth2 client ID
	ClientID string

	// ClientSecret is the OAuth2 client secret
	ClientSecret string

	// RedirectURIs is a list of allowed redirect URIs for the client
	RedirectURIs []string

	// ResponseTypes is a list of allowed response types for the client
	ResponseTypes []string

	// GrantTypes is a list of allowed grant types for the client
	GrantTypes []string

	// Scopes is a list of allowed scopes for the client
	Scopes []string

	// AccessTokenLifespan is the lifespan of access tokens
	AccessTokenLifespan time.Duration

	// AuthorizeCodeLifespan is the lifespan of authorization codes
	AuthorizeCodeLifespan time.Duration

	// IDTokenLifespan is the lifespan of ID tokens
	IDTokenLifespan time.Duration

	// GlobalSecret is the secret used for signing tokens
	GlobalSecret string

	// SendDebugMessagesToClients indicates whether to send debug messages to clients
	SendDebugMessagesToClients bool

	// AllowedPromptValues is a list of allowed prompt values
	AllowedPromptValues []string
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		PrivateKeyPath:             "../../pkg/oidc/sample/keys/private.pem",
		ClientID:                   "myclient",
		ClientSecret:               "mysecret",
		RedirectURIs:               []string{"http://localhost:3000/oauth2/callback"},
		ResponseTypes:              []string{"code", "token", "id_token"},
		GrantTypes:                 []string{"authorization_code", "implicit", "refresh_token"},
		Scopes:                     []string{"openid", "profile", "email"},
		AccessTokenLifespan:        time.Hour,
		AuthorizeCodeLifespan:      time.Minute * 10,
		IDTokenLifespan:            time.Hour,
		GlobalSecret:               "some-very-long-secret-at-least-32-characters",
		SendDebugMessagesToClients: true,
		AllowedPromptValues:        []string{"login", "none", "consent", "select_account"},
	}
}

type Handle struct {
	// JWT Auth for validating user login tokens
	JwtAuth *jwtauth.JWTAuth

	// Global Fosite OAuth2 Provider
	OAuth2Provider fosite.OAuth2Provider

	// RSA Private Key for signing ID tokens
	PrivateKey *rsa.PrivateKey

	// Configuration for the OIDC provider
	Config *Config
}

func loadPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#1 first
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	// If PKCS#1 fails, try PKCS#8
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Ensure parsed key is an RSA private key
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// NewHandle creates a new Handle with default configuration
func NewHandle(jwtAuth *jwtauth.JWTAuth) *Handle {
	return NewHandleWithConfig(jwtAuth, DefaultConfig())
}

// NewHandleWithConfig creates a new Handle with the provided configuration
func NewHandleWithConfig(jwtAuth *jwtauth.JWTAuth, config *Config) *Handle {
	// Generate RSA Key for signing ID Tokens
	privateKey, err := loadPrivateKey(config.PrivateKeyPath)
	if err != nil {
		slog.Error("Could not load RSA Private Key:", "err", err, "path", config.PrivateKeyPath)
	}

	// In-memory OAuth2 storage (Replace with a database in production)
	store := storage.NewExampleStore()

	// Hash the client secret using bcrypt
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(config.ClientSecret), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Could not hash client secret:", "err", err)
	}

	// Register a client with a bcrypt hashed secret
	store.Clients[config.ClientID] = &fosite.DefaultClient{
		ID:            config.ClientID,
		Secret:        hashedSecret, // Bcrypt hashed secret
		RedirectURIs:  config.RedirectURIs,
		ResponseTypes: config.ResponseTypes,
		GrantTypes:    config.GrantTypes,
		Scopes:        config.Scopes,
	}

	// Fosite Config
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        config.AccessTokenLifespan,
		AuthorizeCodeLifespan:      config.AuthorizeCodeLifespan,
		IDTokenLifespan:            config.IDTokenLifespan,
		GlobalSecret:               []byte(config.GlobalSecret),
		SendDebugMessagesToClients: config.SendDebugMessagesToClients,
		AllowedPromptValues:        config.AllowedPromptValues,
	}

	// Create a provider with all enabled handlers
	oauth2Provider := compose.ComposeAllEnabled(fositeConfig, store, privateKey)

	return &Handle{
		OAuth2Provider: oauth2Provider,
		PrivateKey:     privateKey,
		JwtAuth:        jwtAuth,
		Config:         config,
	}
}

func (h *Handle) AuthorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Parse the authorization request
	ar, err := h.OAuth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("[ERROR] NewAuthorizeRequest: %v", err)
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Validate user token
	userClaims, err := h.ValidateUserToken(r)
	var userID string
	if err != nil {
		slog.Warn("[WARNING] ValidateUserToken: ", "err", err)
		// Redirect to login page if not authenticated
		slog.Info("[INFO] Redirecting to login page")
		loginURL := fmt.Sprintf("/login?redirect=%s", url.QueryEscape(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	} else {
		// Extract user ID from claims
		if sub, ok := userClaims["sub"].(string); ok {
			if sub == "" {
				slog.Error("[ERROR] Empty subject claim in token")
				http.Error(w, "Invalid token: empty subject", http.StatusUnauthorized)
				return
			}
			userID = sub
			slog.Info("[INFO] User is authenticated", "userID", userID)
		} else {
			slog.Error("[ERROR] Missing subject claim in token")
			http.Error(w, "Invalid token: missing subject", http.StatusUnauthorized)
			return
		}
	}

	// Create a session for the user with claims and expiration times
	// Extract user information from claims or use defaults if not available
	name := "Unknown User"
	email := ""
	username := ""

	// If we have claims, extract user information from them
	if len(userClaims) > 0 {
		if n, ok := userClaims["name"].(string); ok && n != "" {
			name = n
		}

		if e, ok := userClaims["email"].(string); ok && e != "" {
			email = e
		}

		if u, ok := userClaims["username"].(string); ok && u != "" {
			username = u
		} else if u, ok := userClaims["preferred_username"].(string); ok && u != "" {
			username = u
		}
	}

	// If username is still empty, use the userID as a fallback
	if username == "" {
		username = userID
	}

	// Set expiration times
	now := time.Now()
	accessExpiry := now.Add(1 * time.Hour)
	refreshExpiry := now.Add(30 * 24 * time.Hour)
	idTokenExpiry := now.Add(1 * time.Hour)

	// Create the session with all the information
	session := &DefaultSession{
		Subject: userID,
		Extra: map[string]interface{}{
			"name":  name,
			"email": email,
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:  accessExpiry,
			fosite.RefreshToken: refreshExpiry,
			fosite.IDToken:      idTokenExpiry,
		},
		Username: username,
	}

	slog.Info("[INFO] Created session", "subject", userID, "username", username, "expires", accessExpiry)
	// Generate the authorization response
	response, err := h.OAuth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.Printf("[ERROR] NewAuthorizeResponse: %v", err)
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Log successful authorization
	slog.Info("[INFO] Successful authorization for user", "userID", userID, "client", ar.GetClient().GetID())

	// Write response
	h.OAuth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

func (h *Handle) ValidateUserToken(r *http.Request) (map[string]interface{}, error) {
	// Try to retrieve the token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	var accessToken string

	slog.Info("[INFO] Checking Authorization header", "authHeader", authHeader)
	if authHeader != "" {
		// Format should be: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			accessToken = parts[1]
		}
	}
	// If no Authorization header, check cookies
	if accessToken == "" {
		// Check for both possible cookie names
		cookie, err := r.Cookie("access_token")
		slog.Info("[INFO] Checking cookie", "err", err)
		if err == nil {
			accessToken = cookie.Value
		} else {
			cookie, err = r.Cookie("accessToken")
			slog.Info("[INFO] Checking cookie", "err", err)
			if err == nil {
				slog.Info("[INFO] Found cookie")
				accessToken = cookie.Value
			}
		}
	}

	// If still no token, check URL parameters (for testing/development)
	if accessToken == "" {
		slog.Info("[INFO] Checking URL parameters")
		accessToken = r.URL.Query().Get("access_token")
	}

	// If we still don't have a token, return an error
	if accessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	slog.Info("[INFO] Validating token")

	// Validate the token using JwtAuth
	if h.JwtAuth == nil {
		return nil, fmt.Errorf("JWT authenticator not initialized")
	}

	// Verify the token and get the token object
	token, err := jwtauth.VerifyToken(h.JwtAuth, accessToken)
	if err != nil {
		slog.Error("[ERROR] Token validation failed", "err", err)
		return nil, fmt.Errorf("invalid or expired token")
	}

	// Extract claims from the token
	claims, err := token.AsMap(r.Context())
	if err != nil {
		slog.Error("[ERROR] Failed to extract claims from token", "err", err)
		return nil, fmt.Errorf("failed to extract claims from token: %w", err)
	}

	// Verify that required claims are present
	if claims["sub"] == nil || claims["sub"] == "" {
		slog.Error("[ERROR] Token missing required 'sub' claim")
		return nil, fmt.Errorf("token missing required 'sub' claim")
	}

	slog.Info("[INFO] Token validation successful", "claims", claims)
	return claims, nil
}

func (h *Handle) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Log the request details for debugging
	log.Printf("[INFO] Token request received - Grant Type: %s", r.FormValue("grant_type"))

	// Extract user information from the request
	// In a real implementation, you would validate the authorization code
	// and retrieve the user information from your database
	userID := "user-123456" // Default user ID for testing

	// Try to get the user ID from the authorization code if available
	code := r.FormValue("code")
	if code != "" {
		// In a real implementation, you would look up the authorization code
		// in your database and retrieve the associated user ID
		slog.Info("[INFO] Processing authorization code", "code", code)
		// For now, we'll continue using the default user ID
	}

	// Set default user information
	name := "Test User"
	email := "user@example.com"
	username := "testuser"

	// Set expiration times
	now := time.Now()
	accessExpiry := now.Add(1 * time.Hour)
	refreshExpiry := now.Add(30 * 24 * time.Hour)
	idTokenExpiry := now.Add(1 * time.Hour)

	// Create the session with all the information
	session := &DefaultSession{
		Subject: userID,
		Extra: map[string]interface{}{
			"name":  name,
			"email": email,
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:  accessExpiry,
			fosite.RefreshToken: refreshExpiry,
			fosite.IDToken:      idTokenExpiry,
		},
		Username: username,
	}

	slog.Info("[INFO] Created token session", "subject", userID, "username", username, "expires", accessExpiry)

	// Parse token request
	ar, err := h.OAuth2Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		log.Printf("[ERROR] NewAccessRequest failed: %v", err)
		h.OAuth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Log the client and grant type
	log.Printf("[INFO] Access request - Client: %s, Grant Type: %s",
		ar.GetClient().GetID(), ar.GetGrantTypes()[0])

	// Generate token response
	response, err := h.OAuth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		log.Printf("[ERROR] NewAccessResponse failed: %v", err)
		h.OAuth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Write the response
	h.OAuth2Provider.WriteAccessResponse(ctx, w, ar, response)
}

func (h *Handle) UserInfoEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Extract the access token from the request
	token := fosite.AccessTokenFromRequest(r)

	// Perform token introspection (capture all 3 return values)
	tokenType, accessRequest, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &DefaultSession{})
	if err != nil {
		slog.Error("Token introspection failed", "error", err)
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Ensure the token is an access token
	if tokenType != fosite.AccessToken {
		slog.Error("Invalid token type", "expected", fosite.AccessToken, "got", tokenType)
		http.Error(w, "Invalid token type", http.StatusUnauthorized)
		return
	}

	// Extract the session (OIDC user info)
	session, ok := accessRequest.GetSession().(*DefaultSession)
	if !ok {
		slog.Error("Invalid session data type", "sessionType", fmt.Sprintf("%T", accessRequest.GetSession()))
		http.Error(w, "Invalid session data", http.StatusInternalServerError)
		return
	}

	// Get the subject (user ID) from the session
	userID := session.GetSubject()
	if userID == "" {
		slog.Error("Empty subject in token")
		http.Error(w, "Invalid token: missing subject", http.StatusUnauthorized)
		return
	}

	// Initialize userInfo with required fields
	userInfo := map[string]interface{}{
		"sub": userID,
	}

	// Add username if available
	if username := session.GetUsername(); username != "" {
		userInfo["preferred_username"] = username
	}

	// Add extra claims from the session if available
	if session.Extra != nil {
		for key, value := range session.Extra {
			// Don't override the subject claim
			if key != "sub" {
				userInfo[key] = value
			}
		}
	}

	// Set standard OIDC response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Encode and send the response
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		slog.Error("Failed to encode user info response", "error", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	slog.Info("UserInfo endpoint response sent successfully", "userID", userID)
}

func (h *Handle) JwksEndpoint(w http.ResponseWriter, r *http.Request) {
	// Return the public key for JWT validation
	key := h.PrivateKey.Public().(*rsa.PublicKey)
	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"alg": "RS256",
				"n":   key.N.String(),
				"e":   key.E,
				"kid": "1",   // Key ID
				"use": "sig", // Key usage: signature
			},
		},
	}

	// Respond with JWKS JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// ValidateToken validates an access token and returns the claims
func (h *Handle) ValidateToken(ctx context.Context, token string) (map[string]interface{}, error) {
	// Introspect the token
	tokenType, ar, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &DefaultSession{})
	if err != nil {
		return nil, fmt.Errorf("token introspection failed: %w", err)
	}

	// Ensure it's an access token
	if tokenType != fosite.AccessToken {
		return nil, fmt.Errorf("expected access token but got %s", tokenType)
	}

	// Extract session data
	session, ok := ar.GetSession().(*DefaultSession)
	if !ok {
		return nil, fmt.Errorf("invalid session type")
	}

	// Create claims map
	claims := map[string]interface{}{
		"sub": session.Subject,
	}

	// Add extra claims if available
	if session.Extra != nil {
		for k, v := range session.Extra {
			claims[k] = v
		}
	}

	return claims, nil
}
