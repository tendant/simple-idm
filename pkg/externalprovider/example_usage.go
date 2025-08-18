package externalprovider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
)

// ExampleUsage demonstrates how to set up and use the external provider functionality
func ExampleUsage() {
	// 1. Create repository (in-memory for this example)
	repository := NewInMemoryExternalProviderRepository()

	// 2. Create external provider service
	// You'll need to inject your actual login service and user mapper
	var loginService *login.LoginService // Your existing login service
	var userMapper mapper.UserMapper     // Your existing user mapper

	// Create the external provider service using functional options
	externalProviderService := NewExternalProviderService(
		repository,
		loginService,
		userMapper,
		WithBaseURL("http://localhost:4000"),
		WithStateExpiration(10*time.Minute),
		WithHTTPClient(&http.Client{}),
	)

	// 3. Create token services (you'll need your actual implementations)
	// var tokenService tokengenerator.TokenService
	// var tokenCookieService tokengenerator.TokenCookieService

	// 4. Create API handler (you would import the api package in your main app)
	// handle := externalProviderapi.NewHandle(
	//     externalProviderService,
	//     loginService,
	//     tokenService,
	//     tokenCookieService,
	// ).WithFrontendURL("http://localhost:3000")

	// 5. Create HTTP handler (you would import the api package in your main app)
	// httpHandler := externalProviderapi.Handler(handle)

	// 6. Example: List available providers
	ctx := context.Background()
	providers, err := externalProviderService.GetEnabledProviders(ctx)
	if err != nil {
		slog.Error("Failed to get providers", "error", err)
		return
	}

	fmt.Printf("Available providers:\n")
	for id, provider := range providers {
		fmt.Printf("- %s: %s (%s)\n", id, provider.DisplayName, provider.Description)
	}

	// 7. Example: Initiate OAuth2 flow
	authURL, err := externalProviderService.InitiateOAuth2Flow(ctx, "google", "http://localhost:3000/dashboard")
	if err != nil {
		slog.Error("Failed to initiate OAuth2 flow", "error", err)
		return
	}

	fmt.Printf("Google OAuth2 URL: %s\n", authURL)

	// 8. The HTTP handler can be mounted in your router
	// For example, with chi:
	// r.Mount("/", httpHandler)

	// Note: httpHandler would be created from the API package in your main application
}

// ExampleCustomProvider shows how to add a custom provider
func ExampleCustomProvider() {
	repository := NewInMemoryExternalProviderRepository()

	// Add a custom provider (e.g., LinkedIn)
	linkedinProvider := &ExternalProvider{
		ID:           "linkedin",
		Name:         "linkedin",
		DisplayName:  "LinkedIn",
		ClientID:     "your-linkedin-client-id",
		ClientSecret: "your-linkedin-client-secret",
		AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:  "https://api.linkedin.com/v2/people/~",
		Scopes:       []string{"r_liteprofile", "r_emailaddress"},
		Enabled:      true,
		IconURL:      "https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Bug.svg.original.svg",
		Description:  "Sign in with your LinkedIn account",
	}

	err := repository.CreateProvider(linkedinProvider)
	if err != nil {
		slog.Error("Failed to create LinkedIn provider", "error", err)
		return
	}

	fmt.Println("LinkedIn provider added successfully")
}

// ExampleProviderConfiguration shows different provider configurations
func ExampleProviderConfiguration() {
	// Google configuration
	googleProvider := &ExternalProvider{
		ID:           "google",
		Name:         "google",
		DisplayName:  "Google",
		ClientID:     "your-google-client-id.apps.googleusercontent.com",
		ClientSecret: "your-google-client-secret",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:       []string{"openid", "profile", "email"},
		Enabled:      true,
		IconURL:      "https://developers.google.com/identity/images/g-logo.png",
		Description:  "Sign in with your Google account",
	}

	// Microsoft configuration
	microsoftProvider := &ExternalProvider{
		ID:           "microsoft",
		Name:         "microsoft",
		DisplayName:  "Microsoft",
		ClientID:     "your-microsoft-client-id",
		ClientSecret: "your-microsoft-client-secret",
		AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
		Scopes:       []string{"openid", "profile", "email", "User.Read"},
		Enabled:      true,
		IconURL:      "https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png",
		Description:  "Sign in with your Microsoft account",
	}

	// GitHub configuration
	githubProvider := &ExternalProvider{
		ID:           "github",
		Name:         "github",
		DisplayName:  "GitHub",
		ClientID:     "your-github-client-id",
		ClientSecret: "your-github-client-secret",
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"user:email"},
		Enabled:      true,
		IconURL:      "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
		Description:  "Sign in with your GitHub account",
	}

	fmt.Printf("Provider configurations:\n")
	fmt.Printf("Google: %+v\n", googleProvider)
	fmt.Printf("Microsoft: %+v\n", microsoftProvider)
	fmt.Printf("GitHub: %+v\n", githubProvider)
}

// ExampleIntegrationWithMainApp shows how to integrate with the main application
func ExampleIntegrationWithMainApp() {
	fmt.Println(`
To integrate external provider support with your main application:

1. In cmd/login/main.go, add the external provider service:

   // Initialize external provider repository and service
   externalProviderRepository := externalprovider.NewInMemoryExternalProviderRepository()
   externalProviderService := externalprovider.NewExternalProviderService(
       externalProviderRepository,
       loginService,
       userMapper,
       &externalprovider.ExternalProviderServiceOptions{
           BaseURL: "http://localhost:4000",
       },
   )

   // Create external provider API handler
   externalProviderHandle := externalProviderapi.NewHandle(
       externalProviderService,
       loginService,
       tokenService,
       tokenCookieService,
   ).WithFrontendURL("http://localhost:3000")

   // Mount external provider endpoints (public, no authentication required)
   server.R.Mount("/", externalProviderapi.Handler(externalProviderHandle))

2. Configure your external providers with actual client IDs and secrets:
   - Google: https://console.developers.google.com/
   - Microsoft: https://portal.azure.com/
   - GitHub: https://github.com/settings/applications/new

3. Update your frontend to show "Login with [Provider]" buttons:
   - GET /auth/providers - List available providers
   - Redirect to /auth/{provider} to start OAuth2 flow

4. The callback URLs should be configured in each provider:
   - Google: http://localhost:4000/auth/google/callback
   - Microsoft: http://localhost:4000/auth/microsoft/callback
   - GitHub: http://localhost:4000/auth/github/callback
`)
}
