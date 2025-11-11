// Package externalprovider provides OAuth2 integration with external identity providers.
//
// This package enables authentication through external providers like Google, GitHub,
// Microsoft, LinkedIn, and other OAuth2-compliant services with automatic user creation.
//
// # Overview
//
// The externalprovider package provides:
//   - OAuth2 authentication flow with external providers
//   - Support for Google, GitHub, Microsoft, LinkedIn, and custom providers
//   - Automatic user creation from external accounts
//   - State management for security
//   - Token exchange and user info retrieval
//   - Provider enable/disable management
//
// # Supported Providers
//
//   - **Google** - Google OAuth2
//   - **GitHub** - GitHub OAuth2
//   - **Microsoft** - Microsoft Azure AD / OAuth2
//   - **LinkedIn** - LinkedIn OAuth2
//   - **Custom** - Any OAuth2-compliant provider
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/externalprovider"
//
//	// Create service
//	service := externalprovider.NewExternalProviderService(
//		repo,
//		iamService,
//		loginService,
//		roleService,
//	)
//
//	// Initiate OAuth2 flow
//	authURL, err := service.InitiateOAuth2Flow(ctx, "google", redirectURL)
//
//	// Handle callback
//	loginResult, err := service.HandleOAuth2Callback(ctx, "google", code, state)
//
// # OAuth2 Flow
//
// Step 1: Initiate Authentication
//
//	// User clicks "Login with Google"
//	authURL, err := service.InitiateOAuth2Flow(ctx, "google", "https://app.com/auth/callback")
//	if err != nil {
//		return err
//	}
//
//	// Redirect user to authURL
//	// Example: https://accounts.google.com/o/oauth2/v2/auth?client_id=...
//
// Step 2: Handle Callback
//
//	// Provider redirects back to: https://app.com/auth/callback?code=AUTH_CODE&state=STATE
//	loginResult, err := service.HandleOAuth2Callback(ctx, providerID, code, state)
//	if err != nil {
//		// Handle error: invalid code, state mismatch, etc.
//		return err
//	}
//
//	// User is authenticated
//	// - New user is created automatically if doesn't exist
//	// - Existing user is logged in
//	fmt.Printf("User ID: %s\n", loginResult.User.ID)
//	fmt.Printf("Login ID: %s\n", loginResult.Login.ID)
//
// # Provider Configuration
//
//	// Configure Google provider
//	googleProvider := &externalprovider.ExternalProvider{
//		ID:           "google",
//		Name:         "Google",
//		Type:         "google",
//		ClientID:     "your-client-id.apps.googleusercontent.com",
//		ClientSecret: "your-client-secret",
//		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
//		TokenURL:     "https://oauth2.googleapis.com/token",
//		UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
//		Scopes:       []string{"openid", "profile", "email"},
//		Enabled:      true,
//	}
//
//	err := service.CreateProvider(ctx, googleProvider)
//
// # Provider Management
//
//	// Get all providers
//	providers, err := service.GetAllProviders(ctx)
//	for id, provider := range providers {
//		fmt.Printf("%s: %s (enabled: %v)\n", id, provider.Name, provider.Enabled)
//	}
//
//	// Get enabled providers only
//	enabled, err := service.GetEnabledProviders(ctx)
//
//	// Get specific provider
//	provider, err := service.GetProvider(ctx, "google")
//
//	// Update provider
//	provider.Scopes = append(provider.Scopes, "https://www.googleapis.com/auth/calendar")
//	err = service.UpdateProvider(ctx, provider)
//
//	// Enable/disable provider
//	err = service.EnableProvider(ctx, "github")
//	err = service.DisableProvider(ctx, "microsoft")
//
//	// Delete provider
//	err = service.DeleteProvider(ctx, "linkedin")
//
// # Automatic User Creation
//
// When a user authenticates with an external provider:
//
//	// 1. User info is retrieved from provider
//	userInfo := &ExternalUserInfo{
//		Email: "user@example.com",
//		Name:  "John Doe",
//		// ... other fields
//	}
//
//	// 2. System checks if user exists by email
//	// 3. If not exists, user is created automatically with:
//	//    - Email from provider
//	//    - Name from provider
//	//    - Default role assigned
//	//    - No password (external auth only)
//
//	// 4. User is logged in and LoginResult is returned
//
// # Configuration from Environment
//
//	// Load provider from environment variables
//	// GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_ENABLED
//	// GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_ENABLED
//	// etc.
//
//	providers := loadProvidersFromEnv()
//	for _, provider := range providers {
//		service.CreateProvider(ctx, provider)
//	}
//
// # State Management
//
//	// OAuth2 state is generated and stored for security
//	// State prevents CSRF attacks
//
//	// Clean up expired states periodically
//	err := service.CleanupExpiredStates(ctx)
//
//	// Run as cron job
//	go func() {
//		ticker := time.NewTicker(1 * time.Hour)
//		for range ticker.C {
//			service.CleanupExpiredStates(context.Background())
//		}
//	}()
//
// # Common Patterns
//
// Pattern 1: Social Login Buttons
//
//	func RenderLoginPage(w http.ResponseWriter) {
//		// Get enabled providers
//		providers, _ := externalProviderService.GetEnabledProviders(ctx)
//
//		// Render login buttons
//		for id, provider := range providers {
//			fmt.Fprintf(w, `<a href="/auth/%s">Login with %s</a>`, id, provider.Name)
//		}
//	}
//
//	func HandleProviderLogin(w http.ResponseWriter, r *http.Request) {
//		providerID := chi.URLParam(r, "provider")
//		redirectURL := "https://app.com/auth/callback"
//
//		// Initiate OAuth2 flow
//		authURL, err := externalProviderService.InitiateOAuth2Flow(ctx, providerID, redirectURL)
//		if err != nil {
//			http.Error(w, "provider not found", http.StatusNotFound)
//			return
//		}
//
//		// Redirect to provider
//		http.Redirect(w, r, authURL, http.StatusFound)
//	}
//
// Pattern 2: OAuth2 Callback Handler
//
//	func HandleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
//		providerID := chi.URLParam(r, "provider")
//		code := r.URL.Query().Get("code")
//		state := r.URL.Query().Get("state")
//
//		// Handle OAuth2 callback
//		loginResult, err := externalProviderService.HandleOAuth2Callback(ctx, providerID, code, state)
//		if err != nil {
//			http.Error(w, "authentication failed", http.StatusUnauthorized)
//			return
//		}
//
//		// Generate session token
//		token, err := tokenService.GenerateToken(loginResult.User)
//		if err != nil {
//			http.Error(w, "token generation failed", http.StatusInternalServerError)
//			return
//		}
//
//		// Set cookie and redirect
//		http.SetCookie(w, &http.Cookie{
//			Name:     "session",
//			Value:    token,
//			HttpOnly: true,
//			Secure:   true,
//		})
//
//		http.Redirect(w, r, "/dashboard", http.StatusFound)
//	}
//
// Pattern 3: Account Linking
//
//	func LinkExternalAccount(ctx context.Context, userID uuid.UUID, providerID, code, state string) error {
//		// Verify user is authenticated
//		currentUser := getAuthenticatedUser(ctx)
//		if currentUser.ID != userID {
//			return errors.New("unauthorized")
//		}
//
//		// Handle OAuth2 callback
//		loginResult, err := externalProviderService.HandleOAuth2Callback(ctx, providerID, code, state)
//		if err != nil {
//			return err
//		}
//
//		// Link external account to existing user
//		// (Custom logic to store provider user ID)
//		return linkProviderToUser(userID, providerID, loginResult.User.Email)
//	}
//
// # Security Considerations
//
//  1. Always use HTTPS for OAuth2 flows
//  2. Validate state parameter to prevent CSRF
//  3. Store provider secrets securely (encrypted)
//  4. Use short-lived state tokens (15 minutes)
//  5. Clean up expired states regularly
//  6. Validate redirect URIs strictly
//  7. Log all external authentication attempts
//
// # Best Practices
//
//  1. Request minimal scopes from providers
//  2. Handle provider errors gracefully
//  3. Provide fallback to password login
//  4. Allow users to link multiple providers
//  5. Support provider disconnection
//  6. Cache provider configuration
//
// # Related Packages
//
//   - pkg/iam - User creation and management
//   - pkg/login - Login session management
//   - pkg/role - Role assignment for new users
//   - pkg/oauth2client - OAuth2 client management
package externalprovider
