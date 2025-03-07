package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

	// Fosite Config
	config := &fosite.Config{
		AccessTokenLifespan: time.Hour,
		GlobalSecret:        []byte("some-secret"),
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

	// Parse authorization request
	ar, err := h.OAuth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Normally, you'd authenticate the user before issuing a response
	userID := "123456" // Mocked user ID

	// Create session
	session := &fosite.DefaultSession{
		Subject: userID,
	}

	// Generate authorization response (redirects with code)
	response, err := h.OAuth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	h.OAuth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

func (h *Handle) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Parse token request
	ar, err := h.OAuth2Provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
	if err != nil {
		h.OAuth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Generate token response
	response, err := h.OAuth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		h.OAuth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	h.OAuth2Provider.WriteAccessResponse(ctx, w, ar, response)
}

func (h *Handle) UserInfoEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Extract the access token from the request
	token := fosite.AccessTokenFromRequest(r)

	// Perform token introspection (capture all 3 return values)
	tokenType, accessRequest, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &fosite.DefaultSession{})
	if err != nil {
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
			},
		},
	}

	// Respond with JWKS JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
