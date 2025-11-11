// Package oauth2client provides OAuth2 client management for simple-idm.
//
// This package manages OAuth2 client registration, validation, and credential
// management with support for multiple client types and grant flows.
//
// # Overview
//
// The oauth2client package provides:
//   - OAuth2 client registration and management
//   - Client credential validation
//   - Authorization request validation
//   - Multiple grant type support (authorization_code, client_credentials, etc.)
//   - Client secret encryption
//   - Repository pattern for PostgreSQL, file, and environment-based storage
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/oauth2client"
//
//	// Create service with PostgreSQL repository
//	repo := oauth2client.NewPostgresRepository(db, encryptionKey)
//	service := oauth2client.NewClientService(repo)
//
//	// Get a client
//	client, err := service.GetClient("client-id")
//
//	// Validate client credentials
//	client, err := service.ValidateClientCredentials("client-id", "client-secret")
//
// # Client Registration
//
//	// Create a new OAuth2 client
//	client := &oauth2client.OAuth2Client{
//		ClientID:     "my-app",
//		ClientSecret: "generated-secret",
//		ClientName:   "My Application",
//		RedirectURIs: []string{"https://myapp.com/callback"},
//		GrantTypes:   []string{"authorization_code", "refresh_token"},
//		ResponseTypes: []string{"code"},
//		Scopes:       []string{"openid", "profile", "email"},
//		TokenEndpointAuthMethod: "client_secret_basic",
//	}
//
//	created, err := service.CreateClient(ctx, client)
//	if err != nil {
//		return err
//	}
//
// # Client Credential Validation
//
//	// Validate during token request
//	client, err := service.ValidateClientCredentials(clientID, clientSecret)
//	if err != nil {
//		// Invalid credentials
//		return errors.New("invalid_client")
//	}
//
//	// Client authenticated, proceed with token generation
//
// # Authorization Request Validation
//
//	// Validate during OAuth2 authorization flow
//	client, err := service.ValidateAuthorizationRequest(
//		clientID,
//		redirectURI,
//		responseType,
//		scope,
//	)
//	if err != nil {
//		// Invalid request
//		return err
//	}
//
//	// Request valid, show authorization page
//
// # Client Management
//
//	// List all clients
//	clients := service.ListClients()
//	for clientID, client := range clients {
//		fmt.Printf("%s: %s\n", clientID, client.ClientName)
//	}
//
//	// Update client
//	client.RedirectURIs = append(client.RedirectURIs, "https://newuri.com/callback")
//	updated, err := service.UpdateClient(ctx, client)
//
//	// Delete client
//	err = service.DeleteClient(ctx, clientID)
//
//	// Check if client exists
//	exists, err := service.ClientExists(ctx, clientID)
//
// # Client Secret Generation
//
//	// Generate secure client secret
//	secret, err := service.GenerateClientSecret()
//	if err != nil {
//		return err
//	}
//
//	client.ClientSecret = secret
//
// # Query Clients
//
//	// Get clients by type
//	publicClients, err := service.GetClientsByType(ctx, "public")
//	confidentialClients, err := service.GetClientsByType(ctx, "confidential")
//
//	// Get clients by redirect URI
//	clients, err := service.GetClientsByRedirectURI(ctx, "https://app.com/callback")
//
//	// Get clients by scope
//	clients, err := service.GetClientsByScope(ctx, "admin")
//
//	// Get client count
//	count, err := service.GetClientCount(ctx)
//
// # Repository Implementations
//
// The package provides multiple repository implementations:
//
//	// PostgreSQL (encrypted secrets)
//	postgresRepo := oauth2client.NewPostgresRepository(db, encryptionKey)
//
//	// File-based (for development)
//	fileRepo := oauth2client.NewFileRepository("./clients.json")
//
//	// Environment-based (for simple deployments)
//	envRepo := oauth2client.NewEnvRepository()
//
// # Client Secret Encryption
//
//	// Secrets are automatically encrypted in PostgreSQL
//	encryptionKey := []byte("32-byte-encryption-key-here!!")
//	repo := oauth2client.NewPostgresRepository(db, encryptionKey)
//
//	// Create client - secret is encrypted before storage
//	client, err := service.CreateClient(ctx, &oauth2client.OAuth2Client{
//		ClientID:     "app",
//		ClientSecret: "secret",
//		// ...
//	})
//
//	// Validate - secret is decrypted automatically
//	valid, err := service.ValidateClientCredentials("app", "secret")
//
// # OAuth2 Client Types
//
//	// Confidential client (has secret)
//	&oauth2client.OAuth2Client{
//		ClientID:     "backend-app",
//		ClientSecret: "secret",
//		GrantTypes:   []string{"authorization_code", "client_credentials"},
//		TokenEndpointAuthMethod: "client_secret_basic",
//	}
//
//	// Public client (no secret, PKCE required)
//	&oauth2client.OAuth2Client{
//		ClientID:     "mobile-app",
//		ClientSecret: "", // No secret for public clients
//		GrantTypes:   []string{"authorization_code"},
//		ResponseTypes: []string{"code"},
//		TokenEndpointAuthMethod: "none",
//	}
//
// # Common Patterns
//
// Pattern 1: OAuth2 Authorization Code Flow
//
//	func HandleAuthorization(w http.ResponseWriter, r *http.Request) {
//		clientID := r.URL.Query().Get("client_id")
//		redirectURI := r.URL.Query().Get("redirect_uri")
//		responseType := r.URL.Query().Get("response_type")
//		scope := r.URL.Query().Get("scope")
//
//		// Validate request
//		client, err := clientService.ValidateAuthorizationRequest(
//			clientID, redirectURI, responseType, scope,
//		)
//		if err != nil {
//			http.Error(w, "invalid_request", http.StatusBadRequest)
//			return
//		}
//
//		// Show authorization page
//		showAuthorizationPage(w, client, scope)
//	}
//
// Pattern 2: Token Request Validation
//
//	func HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
//		clientID, clientSecret := extractClientCredentials(r)
//
//		// Validate client
//		client, err := clientService.ValidateClientCredentials(clientID, clientSecret)
//		if err != nil {
//			respondError(w, "invalid_client", http.StatusUnauthorized)
//			return
//		}
//
//		// Validate grant type
//		grantType := r.FormValue("grant_type")
//		if !client.ValidateGrantType(grantType) {
//			respondError(w, "unsupported_grant_type", http.StatusBadRequest)
//			return
//		}
//
//		// Generate token
//		token := generateToken(client, grantType)
//		respondJSON(w, token)
//	}
//
// Pattern 3: Dynamic Client Registration
//
//	func RegisterClient(req RegisterClientRequest) (*oauth2client.OAuth2Client, error) {
//		// Generate client ID
//		clientID := generateClientID()
//
//		// Generate client secret
//		secret, err := clientService.GenerateClientSecret()
//		if err != nil {
//			return nil, err
//		}
//
//		// Create client
//		client := &oauth2client.OAuth2Client{
//			ClientID:     clientID,
//			ClientSecret: secret,
//			ClientName:   req.ClientName,
//			RedirectURIs: req.RedirectURIs,
//			GrantTypes:   req.GrantTypes,
//			ResponseTypes: req.ResponseTypes,
//			Scopes:       req.Scopes,
//		}
//
//		return clientService.CreateClient(ctx, client)
//	}
//
// # Best Practices
//
//  1. Use strong encryption for client secrets (32-byte keys)
//  2. Validate all OAuth2 parameters (redirect_uri, response_type, scope)
//  3. Use PKCE for public clients (mobile/SPA apps)
//  4. Rotate client secrets periodically
//  5. Limit scopes to minimum required
//  6. Validate redirect URIs strictly (no wildcards in production)
//
// # Security Considerations
//
//  1. Never log or expose client secrets
//  2. Use HTTPS for all OAuth2 endpoints
//  3. Implement rate limiting on token endpoints
//  4. Validate redirect URIs exactly (prevent open redirects)
//  5. Use state parameter to prevent CSRF attacks
//  6. Implement proper CORS policies
//
// # Related Packages
//
//   - pkg/oidc - OpenID Connect provider
//   - pkg/pkce - PKCE implementation
//   - pkg/tokengenerator - JWT token generation
package oauth2client
