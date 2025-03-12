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

type Handle struct {
	// JWT Auth for validating user login tokens
	JwtAuth *jwtauth.JWTAuth

	// Global Fosite OAuth2 Provider
	OAuth2Provider fosite.OAuth2Provider

	// RSA Private Key for signing ID tokens
	PrivateKey *rsa.PrivateKey
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile("../../pkg/oidc/sample/keys/private.pem")
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

func NewHandle(jwtAuth *jwtauth.JWTAuth) *Handle {
	// Generate RSA Key for signing ID Tokens
	privateKey, err := loadPrivateKey()
	if err != nil {
		slog.Error("Could not load RSA Private Key:", "err", err)
	}

	// In-memory OAuth2 storage (Replace with a database in production)
	store := storage.NewExampleStore()

	// Hash the client secret using bcrypt
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("mysecret"), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Could not hash client secret:", "err", err)
	}

	// Register a client with a bcrypt hashed secret
	store.Clients["myclient"] = &fosite.DefaultClient{
		ID:            "myclient",
		Secret:        hashedSecret, // Bcrypt hashed secret
		RedirectURIs:  []string{"http://localhost:3000/oauth2/callback"},
		ResponseTypes: []string{"code", "token", "id_token"},
		GrantTypes:    []string{"authorization_code", "implicit", "refresh_token"},
		Scopes:        []string{"openid", "profile", "email"},
	}

	// Fosite Config
	config := &fosite.Config{
		AccessTokenLifespan:        time.Hour,
		AuthorizeCodeLifespan:      time.Minute * 10,
		IDTokenLifespan:            time.Hour,
		GlobalSecret:               []byte("some-very-long-secret-at-least-32-characters"),
		SendDebugMessagesToClients: true, // Helpful for debugging
		AllowedPromptValues:        []string{"login", "none", "consent", "select_account"},
	}

	// Create a provider with all enabled handlers
	oauth2Provider := compose.ComposeAllEnabled(config, store, privateKey)

	return &Handle{
		OAuth2Provider: oauth2Provider,
		PrivateKey:     privateKey,
		JwtAuth:        jwtAuth,
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
	session := &DefaultSession{
		Subject: userID,
		Extra: map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			// Set token expiration times
			fosite.AccessToken:  time.Now().Add(1 * time.Hour),
			fosite.RefreshToken: time.Now().Add(30 * 24 * time.Hour),
			fosite.IDToken:      time.Now().Add(1 * time.Hour),
		},
		Username: "testuser",
	}
	// Generate the authorization response
	response, err := h.OAuth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.Printf("[ERROR] NewAuthorizeResponse: %v", err)
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Log successful authorization
	slog.Info("[INFO] Successful authorization for user", "userToken", userToken, "client", ar.GetClient().GetID())

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
		slog.Info("[INFO] Checking cookie", "err", err, "cookie", cookie)
		if err == nil {
			accessToken = cookie.Value
		} else {
			cookie, err = r.Cookie("accessToken")
			slog.Info("[INFO] Checking cookie", "err", err, "cookie", cookie)
			if err == nil {
				slog.Info("[INFO] Found cookie", "cookie", cookie)
				accessToken = cookie.Value
			}
		}
	}

	// If still no token, check URL parameters (for testing/development)
	if accessToken == "" {
		slog.Info("[INFO] Checking URL parameters", "access_token", accessToken)
		accessToken = r.URL.Query().Get("access_token")
	}

	// If we still don't have a token, return an error
	if accessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	slog.Info("[INFO] Validating token")

	// For development, we'll simulate a valid user token
	// In production, use proper token validation
	if h.JwtAuth != nil {
		_, err := jwtauth.VerifyToken(h.JwtAuth, accessToken)
		if err != nil {
			slog.Error("[ERROR] Token validation failed", "err", err)
			return nil, fmt.Errorf("invalid or expired token")
		}
	}

	// Return simulated claims for testing
	claims := map[string]interface{}{
		"sub":      "user-123456",
		"username": "testuser",
		"name":     "Test User",
		"email":    "test@example.com",
	}

	slog.Info("[INFO] Token validation successful", "claims", claims)
	return claims, nil
}

func (h *Handle) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Log the request details for debugging
	log.Printf("[INFO] Token request received - Grant Type: %s", r.FormValue("grant_type"))

	// Create a default session with claims and expiration times
	session := &DefaultSession{
		Subject: "user-123456", // This should match the subject from the authorization endpoint
		Extra: map[string]interface{}{
			"name":  "Test User",
			"email": "user@example.com",
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			// Set token expiration times
			fosite.AccessToken:  time.Now().Add(1 * time.Hour),
			fosite.RefreshToken: time.Now().Add(30 * 24 * time.Hour),
			fosite.IDToken:      time.Now().Add(1 * time.Hour),
		},
		Username: "testuser",
	}

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
		log.Printf("[ERROR] Token introspection failed: %v", err)
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Ensure the token is an access token
	if tokenType != fosite.AccessToken {
		http.Error(w, "Invalid token type", http.StatusUnauthorized)
		return
	}

	// Extract the session (OIDC user info)
	session, ok := accessRequest.GetSession().(*DefaultSession)
	if !ok {
		http.Error(w, "Invalid session data", http.StatusInternalServerError)
		return
	}

	// Mock user info (Replace with real database lookup)
	userInfo := map[string]string{
		"sub":   session.Subject,
		"name":  "John Doe",
		"email": "john.doe@example.com",
	}

	// Respond with user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
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
