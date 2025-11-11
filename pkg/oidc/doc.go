// Package oidc provides OpenID Connect (OIDC) provider implementation for simple-idm.
//
// This package implements a complete OIDC provider with authorization code flow,
// token generation, user info endpoint, PKCE support, and discovery endpoints.
//
// # Overview
//
// The oidc package provides:
//   - Authorization Code Flow (OAuth 2.0 + OIDC)
//   - PKCE support for public clients
//   - ID Token generation (JWT)
//   - UserInfo endpoint
//   - Token exchange and validation
//   - Authorization code management
//   - Discovery endpoints (.well-known/openid-configuration)
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/oidc"
//
//	// Create OIDC service
//	service := oidc.NewOIDCService(
//		repo,
//		clientService,
//		tokenGenerator,
//		userMapper,
//		oidc.WithBaseURL("https://idm.example.com"),
//		oidc.WithIssuer("https://idm.example.com"),
//		oidc.WithCodeExpiration(10*time.Minute),
//		oidc.WithTokenExpiration(1*time.Hour),
//	)
//
// # Authorization Code Flow
//
// Step 1: Authorization Request
//
//	// User visits: /authorize?client_id=app&redirect_uri=...&response_type=code&scope=openid
//	req := oidc.AuthorizationRequest{
//		ClientID:     "my-app",
//		RedirectURI:  "https://app.com/callback",
//		ResponseType: "code",
//		Scope:        "openid profile email",
//		State:        "random-state",
//	}
//
//	// Process authorization (after user login)
//	resp := service.ProcessAuthorizationRequest(ctx, req)
//	if resp.Error != nil {
//		// Handle error
//		return resp.Error
//	}
//
//	// Redirect user to callback with code
//	// https://app.com/callback?code=AUTH_CODE&state=random-state
//
// Step 2: Token Exchange
//
//	// App exchanges code for tokens
//	tokenReq := oidc.TokenRequest{
//		GrantType:    "authorization_code",
//		Code:         authCode,
//		ClientID:     "my-app",
//		ClientSecret: "secret",
//		RedirectURI:  "https://app.com/callback",
//	}
//
//	tokenResp := service.ProcessTokenRequest(ctx, tokenReq)
//	if tokenResp.Error != nil {
//		return tokenResp.Error
//	}
//
//	// Response contains access_token, id_token, refresh_token
//
// # PKCE Flow (Public Clients)
//
//	// Step 1: Generate code verifier and challenge
//	codeVerifier := generateCodeVerifier()
//	codeChallenge := pkce.GenerateS256Challenge(codeVerifier)
//
//	// Step 2: Authorization request with PKCE
//	code, err := service.GenerateAuthorizationCodeWithPKCE(
//		ctx,
//		clientID,
//		redirectURI,
//		scope,
//		&state,
//		userID,
//		codeChallenge,
//		"S256", // code_challenge_method
//	)
//
//	// Step 3: Token exchange with code verifier
//	authCode, err := service.ValidateAndConsumeAuthorizationCodeWithPKCE(
//		ctx,
//		code,
//		clientID,
//		redirectURI,
//		codeVerifier,
//	)
//
// # ID Token Generation
//
//	// Generate OIDC ID Token (JWT)
//	idToken, err := service.GenerateIDToken(ctx, userID, clientID, scope)
//	if err != nil {
//		return err
//	}
//
//	// ID Token contains claims: sub, iss, aud, exp, iat, etc.
//
// # UserInfo Endpoint
//
//	// Get user information with access token
//	userInfo, err := service.GetUserInfo(ctx, accessToken)
//	if err != nil {
//		return err
//	}
//
//	fmt.Printf("Subject: %s\n", userInfo.Sub)
//	if userInfo.Email != nil {
//		fmt.Printf("Email: %s\n", *userInfo.Email)
//	}
//
// # Token Validation
//
//	// Validate access token
//	claims, err := service.ValidateUserToken(accessToken)
//	if err != nil {
//		// Invalid or expired token
//		return err
//	}
//
//	userID := claims["sub"].(string)
//
// # Authorization Code Management
//
//	// Generate authorization code
//	code, err := service.GenerateAuthorizationCode(
//		ctx,
//		clientID,
//		redirectURI,
//		scope,
//		&state,
//		userID,
//	)
//
//	// Get authorization code details
//	authCode, err := service.GetAuthorizationCode(ctx, code)
//
//	// Validate and consume code (one-time use)
//	authCode, err := service.ValidateAndConsumeAuthorizationCode(
//		ctx,
//		code,
//		clientID,
//		redirectURI,
//	)
//	// Code is now consumed and cannot be reused
//
// # Configuration
//
//	service := oidc.NewOIDCService(
//		repo,
//		clientService,
//		tokenGenerator,
//		userMapper,
//		oidc.WithBaseURL("https://idm.example.com"),
//		oidc.WithIssuer("https://idm.example.com"),
//		oidc.WithLoginURL("https://idm.example.com/login"),
//		oidc.WithCodeExpiration(10*time.Minute),
//		oidc.WithTokenExpiration(1*time.Hour),
//	)
//
// # HTTP Handler Integration
//
//	// The package provides HTTP handlers in handle.go
//	handler := oidc.NewHandler(service)
//
//	// Register OIDC endpoints
//	r.Get("/.well-known/openid-configuration", handler.GetDiscovery)
//	r.Get("/oauth2/authorize", handler.GetAuthorize)
//	r.Post("/oauth2/authorize", handler.PostAuthorize)
//	r.Post("/oauth2/token", handler.PostToken)
//	r.Get("/oauth2/userinfo", handler.GetUserInfo)
//	r.Get("/oauth2/jwks", handler.GetJWKS)
//
// # Common Patterns
//
// Pattern 1: Complete Authorization Code Flow
//
//	func HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
//		// Parse authorization request
//		req := parseAuthorizationRequest(r)
//
//		// Validate client and request
//		resp := oidcService.ProcessAuthorizationRequest(ctx, req)
//		if resp.Error != nil {
//			redirectWithError(w, req.RedirectURI, resp.Error, req.State)
//			return
//		}
//
//		// Check if user is authenticated
//		user := getAuthenticatedUser(r)
//		if user == nil {
//			// Redirect to login with return URL
//			loginURL := oidcService.BuildLoginRedirectURL(r.URL.String())
//			http.Redirect(w, r, loginURL, http.StatusFound)
//			return
//		}
//
//		// Generate authorization code
//		code, err := oidcService.GenerateAuthorizationCode(
//			ctx,
//			req.ClientID,
//			req.RedirectURI,
//			req.Scope,
//			req.State,
//			user.ID.String(),
//		)
//		if err != nil {
//			http.Error(w, "server_error", http.StatusInternalServerError)
//			return
//		}
//
//		// Redirect to callback with code
//		callbackURL, _ := oidcService.BuildCallbackURL(req.RedirectURI, code, req.State)
//		http.Redirect(w, r, callbackURL, http.StatusFound)
//	}
//
// Pattern 2: Token Endpoint Handler
//
//	func HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
//		req := oidc.TokenRequest{
//			GrantType:    r.FormValue("grant_type"),
//			Code:         r.FormValue("code"),
//			RedirectURI:  r.FormValue("redirect_uri"),
//			ClientID:     r.FormValue("client_id"),
//			ClientSecret: r.FormValue("client_secret"),
//			CodeVerifier: r.FormValue("code_verifier"), // PKCE
//		}
//
//		resp := oidcService.ProcessTokenRequest(ctx, req)
//		if resp.Error != nil {
//			respondJSON(w, http.StatusBadRequest, resp.Error)
//			return
//		}
//
//		respondJSON(w, http.StatusOK, resp.TokenResponse)
//	}
//
// Pattern 3: UserInfo Endpoint with Bearer Token
//
//	func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
//		// Extract bearer token
//		authHeader := r.Header.Get("Authorization")
//		if !strings.HasPrefix(authHeader, "Bearer ") {
//			http.Error(w, "invalid_token", http.StatusUnauthorized)
//			return
//		}
//
//		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
//
//		// Get user info
//		userInfo, err := oidcService.GetUserInfo(ctx, accessToken)
//		if err != nil {
//			http.Error(w, "invalid_token", http.StatusUnauthorized)
//			return
//		}
//
//		respondJSON(w, http.StatusOK, userInfo)
//	}
//
// # Security Considerations
//
//  1. Always use HTTPS in production
//  2. Validate redirect URIs strictly (prevent open redirects)
//  3. Use state parameter to prevent CSRF attacks
//  4. Implement PKCE for public clients (mobile/SPA)
//  5. Set appropriate token expiration times
//  6. Rotate signing keys regularly
//  7. Validate all OAuth2 parameters
//  8. Rate-limit token endpoint
//
// # Best Practices
//
//  1. Use PKCE for all clients (even confidential)
//  2. Keep authorization codes short-lived (10 minutes max)
//  3. Implement proper error responses per OAuth2 spec
//  4. Log all authorization and token requests
//  5. Support token revocation
//  6. Provide clear error messages
//
// # Related Packages
//
//   - pkg/oauth2client - OAuth2 client management
//   - pkg/pkce - PKCE implementation
//   - pkg/tokengenerator - JWT token generation
//   - pkg/jwks - JSON Web Key Set management
//   - pkg/wellknown - Discovery endpoints
package oidc
