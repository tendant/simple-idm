package oidc

import (
	"context"
	"fmt"
	"log"

	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/pkce"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

// PKCEExample demonstrates how to use PKCE with the OIDC service
func PKCEExample() {
	// Create dependencies
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	tokenGenerator := &tokengenerator.TempTokenGenerator{}

	// Create OIDC service
	oidcService := NewOIDCServiceWithOptions(
		repository,
		clientService,
		WithCodeExpiration(600),   // 10 minutes
		WithTokenExpiration(3600), // 1 hour
		WithTokenGenerator(tokenGenerator),
	)

	ctx := context.Background()

	// Step 1: Client generates PKCE parameters
	fmt.Println("=== Step 1: Generate PKCE Parameters ===")

	// Generate code verifier
	codeVerifier, err := pkce.GenerateCodeVerifier()
	if err != nil {
		log.Fatalf("Failed to generate code verifier: %v", err)
	}
	fmt.Printf("Code Verifier: %s\n", codeVerifier.Value)

	// Generate code challenge using S256 method
	codeChallenge, err := codeVerifier.GenerateCodeChallenge(pkce.ChallengeS256)
	if err != nil {
		log.Fatalf("Failed to generate code challenge: %v", err)
	}
	fmt.Printf("Code Challenge: %s\n", codeChallenge.Value)
	fmt.Printf("Code Challenge Method: %s\n", codeChallenge.Method)

	// Step 2: Authorization request with PKCE
	fmt.Println("\n=== Step 2: Authorization Request with PKCE ===")

	clientID := "test-client"
	redirectURI := "https://example.com/callback"
	scope := "openid profile"
	userID := "user123"
	state := "random-state"

	// Generate authorization code with PKCE
	authCode, err := oidcService.GenerateAuthorizationCodeWithPKCE(
		ctx,
		clientID,
		redirectURI,
		scope,
		&state,
		userID,
		codeChallenge.Value,
		string(codeChallenge.Method),
	)
	if err != nil {
		log.Fatalf("Failed to generate authorization code: %v", err)
	}
	fmt.Printf("Authorization Code: %s\n", authCode)

	// Step 3: Token exchange with PKCE validation
	fmt.Println("\n=== Step 3: Token Exchange with PKCE Validation ===")

	// Validate and consume authorization code with PKCE
	validatedAuthCode, err := oidcService.ValidateAndConsumeAuthorizationCodeWithPKCE(
		ctx,
		authCode,
		clientID,
		redirectURI,
		codeVerifier.Value,
	)
	if err != nil {
		log.Fatalf("Failed to validate authorization code with PKCE: %v", err)
	}
	fmt.Printf("PKCE validation successful!\n")
	fmt.Printf("User ID: %s\n", validatedAuthCode.UserID)
	fmt.Printf("Scope: %s\n", validatedAuthCode.Scope)

	// Step 4: Generate access token
	fmt.Println("\n=== Step 4: Generate Access Token ===")

	accessToken, err := oidcService.GenerateAccessToken(ctx, userID, clientID, scope)
	if err != nil {
		log.Fatalf("Failed to generate access token: %v", err)
	}
	fmt.Printf("Access Token: %s\n", accessToken)

	fmt.Println("\n=== PKCE Flow Complete! ===")
}

// PKCEFailureExample demonstrates PKCE validation failure scenarios
func PKCEFailureExample() {
	// Create dependencies
	repository := NewInMemoryOIDCRepository()
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())

	// Create OIDC service
	oidcService := NewOIDCServiceWithOptions(repository, clientService)

	ctx := context.Background()

	fmt.Println("=== PKCE Failure Scenarios ===")

	// Generate valid PKCE parameters
	codeVerifier, _ := pkce.GenerateCodeVerifier()
	codeChallenge, _ := codeVerifier.GenerateCodeChallenge(pkce.ChallengeS256)

	// Create authorization code with PKCE
	authCode, _ := oidcService.GenerateAuthorizationCodeWithPKCE(
		ctx,
		"test-client",
		"https://example.com/callback",
		"openid",
		nil,
		"user123",
		codeChallenge.Value,
		string(codeChallenge.Method),
	)

	// Scenario 1: Missing code verifier
	fmt.Println("\n1. Missing Code Verifier:")
	_, err := oidcService.ValidateAndConsumeAuthorizationCodeWithPKCE(
		ctx,
		authCode,
		"test-client",
		"https://example.com/callback",
		"", // Empty code verifier
	)
	if err != nil {
		fmt.Printf("   Expected error: %v\n", err)
	}

	// Scenario 2: Wrong code verifier
	fmt.Println("\n2. Wrong Code Verifier:")
	wrongVerifier, _ := pkce.GenerateCodeVerifier()
	_, err = oidcService.ValidateAndConsumeAuthorizationCodeWithPKCE(
		ctx,
		authCode,
		"test-client",
		"https://example.com/callback",
		wrongVerifier.Value,
	)
	if err != nil {
		fmt.Printf("   Expected error: %v\n", err)
	}

	fmt.Println("\n=== PKCE Security Working Correctly! ===")
}
