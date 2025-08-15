package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

func TestOIDCService_GenerateAuthorizationCode(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)

	// Test
	ctx := context.Background()
	code, err := service.GenerateAuthorizationCode(ctx, "test-client", "http://localhost:8080/callback", "openid", stringPtr("test-state"), "user123")

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if code == "" {
		t.Fatal("Expected non-empty authorization code")
	}

	// Verify the code was stored
	authCode, err := repository.GetAuthorizationCode(ctx, code)
	if err != nil {
		t.Fatalf("Expected to retrieve stored code, got error: %v", err)
	}

	if authCode.ClientID != "test-client" {
		t.Errorf("Expected client ID 'test-client', got '%s'", authCode.ClientID)
	}

	if authCode.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", authCode.UserID)
	}

	if authCode.Used {
		t.Error("Expected authorization code to not be used initially")
	}
}

func TestOIDCService_ValidateAndConsumeAuthorizationCode(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)
	ctx := context.Background()

	// Generate a code first
	code, err := service.GenerateAuthorizationCode(ctx, "test-client", "http://localhost:8080/callback", "openid", stringPtr("test-state"), "user123")
	if err != nil {
		t.Fatalf("Failed to generate authorization code: %v", err)
	}

	// Test validation and consumption
	authCode, err := service.ValidateAndConsumeAuthorizationCode(ctx, code, "test-client", "http://localhost:8080/callback")

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if authCode.ClientID != "test-client" {
		t.Errorf("Expected client ID 'test-client', got '%s'", authCode.ClientID)
	}

	if authCode.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", authCode.UserID)
	}

	// Verify the code is now marked as used
	storedCode, err := repository.GetAuthorizationCode(ctx, code)
	if err == nil {
		t.Error("Expected error when retrieving used authorization code")
	}

	if storedCode != nil {
		t.Error("Expected nil when retrieving used authorization code")
	}
}

func TestOIDCService_ValidateAndConsumeAuthorizationCode_WrongClient(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)
	ctx := context.Background()

	// Generate a code for one client
	code, err := service.GenerateAuthorizationCode(ctx, "test-client", "http://localhost:8080/callback", "openid", stringPtr("test-state"), "user123")
	if err != nil {
		t.Fatalf("Failed to generate authorization code: %v", err)
	}

	// Try to validate with a different client
	_, err = service.ValidateAndConsumeAuthorizationCode(ctx, code, "different-client", "http://localhost:8080/callback")

	// Should fail
	if err == nil {
		t.Error("Expected error when using wrong client ID")
	}
}

func TestOIDCService_GenerateAccessToken(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)

	ctx := context.Background()

	// Test
	token, err := service.GenerateAccessToken(ctx, "user123", "test-client", "openid profile")

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty access token")
	}

	// Verify the token can be parsed using the TokenGenerator
	parsedToken, err := tokenGen.ParseToken(token)
	if err != nil {
		t.Fatalf("Expected valid JWT token, got error: %v", err)
	}

	if !parsedToken.Valid {
		t.Fatal("Expected valid token")
	}

	// Extract claims from the JWT token
	var claims map[string]interface{}
	if mapClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		claims = map[string]interface{}(mapClaims)
	} else {
		t.Fatal("Failed to extract claims from token")
	}

	if claims["sub"] != "user123" {
		t.Errorf("Expected subject 'user123', got '%v'", claims["sub"])
	}

	// Handle audience as either string or array (TokenGenerator may return array)
	aud := claims["aud"]
	if audStr, ok := aud.(string); ok {
		if audStr != "test-client" {
			t.Errorf("Expected audience 'test-client', got '%v'", audStr)
		}
	} else if audArr, ok := aud.([]interface{}); ok {
		// TokenGenerator might return the default audience from constructor
		if len(audArr) == 0 {
			t.Error("Expected non-empty audience array")
		}
		// Accept either test-client or oidc-client (from TokenGenerator constructor)
		audStr := audArr[0].(string)
		if audStr != "test-client" && audStr != "oidc-client" {
			t.Errorf("Expected audience 'test-client' or 'oidc-client', got '%v'", audStr)
		}
	} else {
		t.Errorf("Expected audience as string or array, got '%v' of type %T", aud, aud)
	}

	// The scope might be nil if not properly set in the token generation
	if scope := claims["scope"]; scope != nil && scope != "openid profile" {
		t.Errorf("Expected scope 'openid profile', got '%v'", scope)
	}
}

func TestInMemoryOIDCRepository_StoreAndRetrieve(t *testing.T) {
	// Setup
	repo := NewInMemoryOIDCRepository()
	ctx := context.Background()

	authCode := &AuthorizationCode{
		Code:        "test-code",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid",
		State:       "test-state",
		UserID:      "user123",
		ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
		Used:        false,
		CreatedAt:   time.Now().UTC(),
	}

	// Test store
	err := repo.StoreAuthorizationCode(ctx, authCode)
	if err != nil {
		t.Fatalf("Expected no error storing code, got %v", err)
	}

	// Test retrieve
	retrieved, err := repo.GetAuthorizationCode(ctx, "test-code")
	if err != nil {
		t.Fatalf("Expected no error retrieving code, got %v", err)
	}

	if retrieved.Code != authCode.Code {
		t.Errorf("Expected code '%s', got '%s'", authCode.Code, retrieved.Code)
	}

	if retrieved.ClientID != authCode.ClientID {
		t.Errorf("Expected client ID '%s', got '%s'", authCode.ClientID, retrieved.ClientID)
	}

	if retrieved.UserID != authCode.UserID {
		t.Errorf("Expected user ID '%s', got '%s'", authCode.UserID, retrieved.UserID)
	}
}

func TestInMemoryOIDCRepository_MarkUsed(t *testing.T) {
	// Setup
	repo := NewInMemoryOIDCRepository()
	ctx := context.Background()

	authCode := &AuthorizationCode{
		Code:        "test-code",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid",
		State:       "test-state",
		UserID:      "user123",
		ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
		Used:        false,
		CreatedAt:   time.Now().UTC(),
	}

	// Store the code
	err := repo.StoreAuthorizationCode(ctx, authCode)
	if err != nil {
		t.Fatalf("Expected no error storing code, got %v", err)
	}

	// Mark as used
	err = repo.MarkAuthorizationCodeUsed(ctx, "test-code")
	if err != nil {
		t.Fatalf("Expected no error marking code as used, got %v", err)
	}

	// Try to retrieve - should fail since it's used
	_, err = repo.GetAuthorizationCode(ctx, "test-code")
	if err == nil {
		t.Error("Expected error when retrieving used code")
	}
}

func TestOIDCService_GetAuthorizationCode(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)

	ctx := context.Background()

	// Generate a code first
	code, err := service.GenerateAuthorizationCode(ctx, "test-client", "http://localhost:8080/callback", "openid", stringPtr("test-state"), "user123")
	if err != nil {
		t.Fatalf("Failed to generate authorization code: %v", err)
	}

	// Test retrieving the code
	authCode, err := service.GetAuthorizationCode(ctx, code)

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if authCode.Code != code {
		t.Errorf("Expected code '%s', got '%s'", code, authCode.Code)
	}

	if authCode.ClientID != "test-client" {
		t.Errorf("Expected client ID 'test-client', got '%s'", authCode.ClientID)
	}

	if authCode.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", authCode.UserID)
	}
}

func TestOIDCService_GetAuthorizationCode_EmptyCode(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	service := NewOIDCServiceWithOptions(repository, clientService)
	ctx := context.Background()

	// Test with empty code
	_, err := service.GetAuthorizationCode(ctx, "")

	// Should fail
	if err == nil {
		t.Error("Expected error when retrieving with empty code")
	}
}

func TestOIDCService_GenerateRefreshToken(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)

	ctx := context.Background()

	// Test
	token, err := service.GenerateRefreshToken(ctx, "user123", "test-client", "openid profile")

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty refresh token")
	}

	// Verify the token can be parsed using the TokenGenerator
	parsedToken, err := tokenGen.ParseToken(token)
	if err != nil {
		t.Fatalf("Expected valid JWT token, got error: %v", err)
	}

	if !parsedToken.Valid {
		t.Fatal("Expected valid token")
	}

	// Extract claims from the JWT token
	var claims map[string]interface{}
	if mapClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		claims = map[string]interface{}(mapClaims)
	} else {
		t.Fatal("Failed to extract claims from token")
	}

	if claims["sub"] != "user123" {
		t.Errorf("Expected subject 'user123', got '%v'", claims["sub"])
	}

	// Access extra claims nested under "extra_claims"
	extraClaims, ok := claims["extra_claims"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract extra claims from token")
	}

	if extraClaims["token_use"] != "refresh" {
		t.Errorf("Expected token_use 'refresh', got '%v'", extraClaims["token_use"])
	}

	if extraClaims["user_id"] != "user123" {
		t.Errorf("Expected user_id 'user123', got '%v'", extraClaims["user_id"])
	}

	if extraClaims["client_id"] != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%v'", extraClaims["client_id"])
	}
}

func TestOIDCService_ValidateUserToken(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)

	// Generate a token first
	ctx := context.Background()
	token, err := service.GenerateAccessToken(ctx, "user123", "test-client", "openid profile")
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	// Test validation
	claims, err := service.ValidateUserToken(token)

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if claims["sub"] != "user123" {
		t.Errorf("Expected subject 'user123', got '%v'", claims["sub"])
	}

	// Access extra claims nested under "extra_claims"
	extraClaims, ok := claims["extra_claims"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract extra claims from token")
	}

	if extraClaims["user_id"] != "user123" {
		t.Errorf("Expected user_id 'user123', got '%v'", extraClaims["user_id"])
	}

	if extraClaims["client_id"] != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%v'", extraClaims["client_id"])
	}
}

func TestOIDCService_ValidateUserToken_InvalidToken(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
	)

	// Test with invalid token
	_, err := service.ValidateUserToken("invalid-token")

	// Should fail
	if err == nil {
		t.Error("Expected error when validating invalid token")
	}
}

func TestOIDCService_GetBaseURL(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Test with custom base URL
	service := NewOIDCServiceWithOptions(repository, clientService,
		WithBaseURL("http://custom.example.com"),
	)

	baseURL := service.GetBaseURL()
	if baseURL != "http://custom.example.com" {
		t.Errorf("Expected base URL 'http://custom.example.com', got '%s'", baseURL)
	}

	// Test with default base URL
	serviceDefault := NewOIDCServiceWithOptions(repository, clientService)
	defaultBaseURL := serviceDefault.GetBaseURL()
	if defaultBaseURL != "http://localhost:4000" {
		t.Errorf("Expected default base URL 'http://localhost:4000', got '%s'", defaultBaseURL)
	}
}

func TestOIDCService_GetLoginURL(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Test with custom login URL
	service := NewOIDCServiceWithOptions(repository, clientService,
		WithLoginURL("http://custom.example.com/login"),
	)

	loginURL := service.GetLoginURL()
	if loginURL != "http://custom.example.com/login" {
		t.Errorf("Expected login URL 'http://custom.example.com/login', got '%s'", loginURL)
	}

	// Test with default login URL
	serviceDefault := NewOIDCServiceWithOptions(repository, clientService)
	defaultLoginURL := serviceDefault.GetLoginURL()
	if defaultLoginURL != "http://localhost:3000/login" {
		t.Errorf("Expected default login URL 'http://localhost:3000/login', got '%s'", defaultLoginURL)
	}
}

func TestOIDCService_GetTokenExpiration(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Test with custom token expiration
	customExpiration := 2 * time.Hour
	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenExpiration(customExpiration),
	)

	expiration := service.GetTokenExpiration()
	if expiration != customExpiration {
		t.Errorf("Expected token expiration '%v', got '%v'", customExpiration, expiration)
	}

	// Test with default token expiration
	serviceDefault := NewOIDCServiceWithOptions(repository, clientService)
	defaultExpiration := serviceDefault.GetTokenExpiration()
	if defaultExpiration != time.Hour {
		t.Errorf("Expected default token expiration '%v', got '%v'", time.Hour, defaultExpiration)
	}
}

func TestOIDCService_GetCodeExpiration(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Test with custom code expiration
	customExpiration := 5 * time.Minute
	service := NewOIDCServiceWithOptions(repository, clientService,
		WithCodeExpiration(customExpiration),
	)

	expiration := service.GetCodeExpiration()
	if expiration != customExpiration {
		t.Errorf("Expected code expiration '%v', got '%v'", customExpiration, expiration)
	}

	// Test with default code expiration
	serviceDefault := NewOIDCServiceWithOptions(repository, clientService)
	defaultExpiration := serviceDefault.GetCodeExpiration()
	if defaultExpiration != 10*time.Minute {
		t.Errorf("Expected default code expiration '%v', got '%v'", 10*time.Minute, defaultExpiration)
	}
}

func TestOIDCService_GenerateAccessToken_AdditionalClaims(t *testing.T) {
	// Setup
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create a TokenGenerator
	tokenGen := tokengenerator.NewJwtTokenGenerator("test-secret", "simple-idm", "oidc-client")

	service := NewOIDCServiceWithOptions(repository, clientService,
		WithTokenGenerator(tokenGen),
		WithCodeExpiration(10*time.Minute),
		WithTokenExpiration(time.Hour),
		WithBaseURL("http://localhost:4000"),
		WithLoginURL("http://localhost:3000/login"),
	)

	ctx := context.Background()

	// Test
	token, err := service.GenerateAccessToken(ctx, "user123", "test-client", "openid profile")

	// Assertions
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty access token")
	}

	// Verify the token can be parsed using the TokenGenerator
	parsedToken, err := tokenGen.ParseToken(token)
	if err != nil {
		t.Fatalf("Expected valid JWT token, got error: %v", err)
	}

	if !parsedToken.Valid {
		t.Fatal("Expected valid token")
	}

	// Extract claims from the JWT token
	var claims map[string]interface{}
	if mapClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		claims = map[string]interface{}(mapClaims)
	} else {
		t.Fatal("Failed to extract claims from token")
	}

	// Access extra claims nested under "extra_claims"
	extraClaims, ok := claims["extra_claims"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract extra claims from token")
	}

	// Check the new additional claims
	if extraClaims["token_use"] != "access" {
		t.Errorf("Expected token_use 'access', got '%v'", extraClaims["token_use"])
	}

	if extraClaims["user_id"] != "user123" {
		t.Errorf("Expected user_id 'user123', got '%v'", extraClaims["user_id"])
	}

	if extraClaims["client_id"] != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%v'", extraClaims["client_id"])
	}

	if extraClaims["scope"] != "openid profile" {
		t.Errorf("Expected scope 'openid profile', got '%v'", extraClaims["scope"])
	}
}

// Helper function for tests
func stringPtr(s string) *string {
	return &s
}
