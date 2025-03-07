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
	"os"

	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
)

type Handle struct {
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

func NewHandle() *Handle {
	// Generate RSA Key for signing ID Tokens
	privateKey, err := loadPrivateKey()
	if err != nil {
		slog.Error("Could not load RSA Private Key:", "err", err)
	}

	// In-memory OAuth2 storage (Replace with a database in production)
	store := storage.NewExampleStore()

	// Register a client with a plain text secret for testing
	// In production, you should use a hashed secret
	store.Clients["myclient"] = &fosite.DefaultClient{
		ID:            "myclient",
		Secret:        []byte("mysecret"), // Plain text secret for testing
		RedirectURIs:  []string{"http://localhost:8080/callback"},
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

	// Define Fosite configuration with OIDC support
	oauth2Provider := compose.ComposeAllEnabled(
		config,
		store,
		privateKey,
	)

	return &Handle{
		OAuth2Provider: oauth2Provider,
		PrivateKey:     privateKey,
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

	// In a real application, you would check if the user is logged in
	// If not, redirect to a login page and then come back to this endpoint
	// For now, we'll simulate a logged-in user
	
	// Mock user authentication (in production, check session or database)
	userID := "user-123456"
	
	// Create a session for the user with claims
	session := &fosite.DefaultSession{
		Subject: userID,
		Extra: map[string]interface{}{
			"name": "Test User",
			"email": "user@example.com",
		},
	}

	// For demonstration purposes, automatically approve the request
	// In a real application, you would show a consent screen to the user
	// and only proceed if they approve
	
	// Generate the authorization response
	response, err := h.OAuth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.Printf("[ERROR] NewAuthorizeResponse: %v", err)
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Log successful authorization
	log.Printf("[INFO] Successful authorization for user: %s, client: %s", userID, ar.GetClient().GetID())

	// Write response
	h.OAuth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

func (h *Handle) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Log the request details for debugging
	log.Printf("[INFO] Token request received - Grant Type: %s", r.FormValue("grant_type"))
	
	// Create a default session with claims
	session := &fosite.DefaultSession{
		Subject: "user-123456", // This should match the subject from the authorization endpoint
		Extra: map[string]interface{}{
			"name": "Test User",
			"email": "user@example.com",
		},
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

	// Log success
	log.Printf("[INFO] Successfully issued tokens to client: %s", ar.GetClient().GetID())

	// Write the response
	h.OAuth2Provider.WriteAccessResponse(ctx, w, ar, response)
}

func (h *Handle) UserInfoEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Extract the access token from the request
	token := fosite.AccessTokenFromRequest(r)

	// Perform token introspection (capture all 3 return values)
	tokenType, accessRequest, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &fosite.DefaultSession{})
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
	session, ok := accessRequest.GetSession().(*fosite.DefaultSession)
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
				"kid": "1", // Key ID
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
	tokenType, ar, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &fosite.DefaultSession{})
	if err != nil {
		return nil, fmt.Errorf("token introspection failed: %w", err)
	}

	// Ensure it's an access token
	if tokenType != fosite.AccessToken {
		return nil, fmt.Errorf("expected access token but got %s", tokenType)
	}

	// Extract session data
	session, ok := ar.GetSession().(*fosite.DefaultSession)
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
