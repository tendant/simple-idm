package main

import (
	"context"
	"fmt"
	"log"

	"github.com/tendant/simple-idm/pkg/oauth2client"
	"github.com/tendant/simple-idm/pkg/oidc"
	"github.com/tendant/simple-idm/pkg/pkce"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

func main() {
	fmt.Println("=== PKCE Demo ===")

	// Initialize services
	clientRepo := oauth2client.NewInMemoryOAuth2ClientRepository()
	oidcRepo := oidc.NewInMemoryOIDCRepository()

	clientService := oauth2client.NewClientService(clientRepo)
	tokenGen := tokengenerator.NewJwtTokenGenerator("secret-key", "simple-idm", "test-client")
	oidcService := oidc.NewOIDCServiceWithOptions(oidcRepo, clientService,
		oidc.WithBaseURL("http://localhost:4000"),
		oidc.WithLoginURL("http://localhost:3000/login"),
		oidc.WithTokenGenerator(tokenGen))

	// Register a test client
	client := &oauth2client.OAuth2Client{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		RequirePKCE:  true,
	}
	err := clientRepo.CreateClient(context.Background(), client)
	if err != nil {
		log.Fatal("Failed to store client:", err)
	}

	fmt.Println("✓ Test client registered")

	// 1. Generate PKCE parameters
	codeVerifier, err := pkce.GenerateCodeVerifier()
	if err != nil {
		log.Fatal("Failed to generate code verifier:", err)
	}

	codeChallenge, err := codeVerifier.GenerateCodeChallenge(pkce.ChallengeS256)
	if err != nil {
		log.Fatal("Failed to generate code challenge:", err)
	}

	fmt.Printf("✓ Generated PKCE parameters:\n")
	fmt.Printf("  Code Verifier: %s\n", codeVerifier.Value)
	fmt.Printf("  Code Challenge: %s\n", codeChallenge.Value)

	// 2. Generate authorization code with PKCE
	ctx := context.Background()
	testState := "test-state"
	authCode, err := oidcService.GenerateAuthorizationCodeWithPKCE(
		ctx, "test-client", "http://localhost:8080/callback", "openid profile", &testState, "user123",
		codeChallenge.Value, "S256")
	if err != nil {
		log.Fatal("Failed to generate authorization code:", err)
	}

	fmt.Printf("✓ Generated authorization code: %s\n", authCode)

	// 3. Validate and consume authorization code with PKCE
	retrievedCode, err := oidcService.ValidateAndConsumeAuthorizationCodeWithPKCE(
		ctx, authCode, "test-client", "http://localhost:8080/callback", codeVerifier.Value)
	if err != nil {
		log.Fatal("Failed to validate authorization code:", err)
	}

	fmt.Printf("✓ Successfully validated authorization code with PKCE\n")
	fmt.Printf("  User ID: %s\n", retrievedCode.UserID)
	fmt.Printf("  Scope: %s\n", retrievedCode.Scope)
	fmt.Printf("  State: %s\n", retrievedCode.State)

	// 4. Test failure case - wrong code verifier
	fmt.Println("\n=== Testing failure case ===")
	wrongVerifier, _ := pkce.GenerateCodeVerifier()

	// Generate another auth code for the failure test
	authCode2, err := oidcService.GenerateAuthorizationCodeWithPKCE(
		ctx, "test-client", "http://localhost:8080/callback", "openid profile", &testState, "user123",
		codeChallenge.Value, "S256")
	if err != nil {
		log.Fatal("Failed to generate second authorization code:", err)
	}

	_, err = oidcService.ValidateAndConsumeAuthorizationCodeWithPKCE(
		ctx, authCode2, "test-client", "http://localhost:8080/callback", wrongVerifier.Value)
	if err != nil {
		fmt.Printf("✓ Correctly rejected wrong code verifier: %s\n", err.Error())
	} else {
		log.Fatal("Should have failed with wrong code verifier")
	}

	fmt.Println("\n=== PKCE Demo Complete ===")
	fmt.Println("✓ All PKCE functionality working correctly!")
}
