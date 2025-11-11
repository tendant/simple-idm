// Package wellknown provides OAuth 2.0 and OpenID Connect discovery endpoints.
//
// This package implements RFC 8414 (OAuth 2.0 Authorization Server Metadata),
// RFC 9728 (OAuth 2.0 Protected Resource Metadata), and OpenID Connect Discovery 1.0.
// These well-known endpoints allow clients to automatically discover OAuth2/OIDC
// configuration without manual setup.
//
// # Features
//
//   - RFC 8414 compliant authorization server metadata
//   - RFC 9728 compliant protected resource metadata (MCP support)
//   - OpenID Connect Discovery 1.0 support
//   - JWKS endpoint for public key distribution
//   - Configurable scopes and endpoints
//   - CORS-enabled for browser-based clients
//   - Cache-friendly responses (1-hour cache)
//
// # Endpoints Provided
//
//   - /.well-known/oauth-authorization-server - OAuth2 server metadata (RFC 8414)
//   - /.well-known/oauth-protected-resource - Protected resource metadata (RFC 9728)
//   - /.well-known/openid-configuration - OpenID Connect discovery
//   - /.well-known/jwks.json - JSON Web Key Set (public keys)
//   - /jwks - Alternative JWKS endpoint
//
// # Basic Usage
//
// ## Simple Setup
//
//	import (
//	    "net/http"
//	    "github.com/tendant/simple-idm/pkg/wellknown"
//	    "github.com/tendant/simple-idm/pkg/jwks"
//	)
//
//	func main() {
//	    // Configure well-known endpoints
//	    config := wellknown.Config{
//	        ResourceURI:            "https://api.example.com",
//	        AuthorizationServerURI: "https://auth.example.com",
//	        BaseURL:                "https://auth.example.com",
//	        Scopes:                 []string{"openid", "profile", "email"},
//	    }
//
//	    // Create handler
//	    handler := wellknown.NewHandler(config)
//
//	    // Register routes with standard library mux
//	    mux := http.NewServeMux()
//	    handler.RegisterRoutes(mux)
//
//	    http.ListenAndServe(":8080", mux)
//	}
//
// ## With JWKS Service
//
//	import "github.com/tendant/simple-idm/pkg/jwks"
//
//	// Create JWKS service
//	jwksService, err := jwks.NewJWKSServiceWithInMemoryStorage()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create handler with JWKS support
//	handler := wellknown.NewHandler(config,
//	    wellknown.WithJWKSService(jwksService),
//	)
//
//	mux := http.NewServeMux()
//	handler.RegisterRoutes(mux)
//
// Now clients can discover your public keys at:
//   - https://auth.example.com/.well-known/jwks.json
//   - https://auth.example.com/jwks
//
// ## Custom Router Integration
//
//	import "github.com/go-chi/chi/v5"
//
//	// chi router example
//	r := chi.NewRouter()
//
//	handler := wellknown.NewHandler(config, wellknown.WithJWKSService(jwksService))
//
//	// Register with custom function
//	handler.RegisterRoutesWithPrefix(func(pattern string, handlerFunc http.HandlerFunc) {
//	    r.Get(pattern, handlerFunc)
//	})
//
// # Configuration
//
// ## Config Structure
//
//	type Config struct {
//	    // The canonical URI of your resource server
//	    ResourceURI string  // e.g., "https://api.example.com"
//
//	    // The URI of your authorization server (often same as ResourceURI)
//	    AuthorizationServerURI string  // e.g., "https://auth.example.com"
//
//	    // Base URL for constructing endpoint URLs
//	    BaseURL string  // e.g., "https://auth.example.com"
//
//	    // OAuth2 scopes your server supports
//	    Scopes []string  // e.g., []string{"openid", "profile", "email", "groups"}
//
//	    // Optional: Documentation URL for developers
//	    ResourceDocumentation string  // e.g., "https://docs.example.com/api"
//	}
//
// ## Default Scopes
//
// If no scopes are provided, defaults to:
//   - openid (required for OIDC)
//   - profile (user profile claims)
//   - email (email address)
//   - groups (group memberships)
//
// ## Endpoint URLs
//
// The handler automatically constructs standard endpoint URLs:
//   - Authorization: {BaseURL}/oauth2/authorize
//   - Token: {BaseURL}/api/oauth2/token
//   - UserInfo: {BaseURL}/api/oauth2/userinfo
//   - JWKS: {BaseURL}/api/oauth2/jwks
//
// # OAuth 2.0 Authorization Server Metadata (RFC 8414)
//
// Endpoint: /.well-known/oauth-authorization-server
//
//	// Example response
//	{
//	    "issuer": "https://auth.example.com",
//	    "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
//	    "token_endpoint": "https://auth.example.com/api/oauth2/token",
//	    "jwks_uri": "https://auth.example.com/api/oauth2/jwks",
//	    "scopes_supported": ["openid", "profile", "email"],
//	    "response_types_supported": ["code"],
//	    "grant_types_supported": ["authorization_code"],
//	    "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
//	    "code_challenge_methods_supported": ["S256"],  // PKCE
//	    "resource_parameter_supported": true
//	}
//
// Clients can use this to auto-configure:
//
//	// Client-side auto-configuration
//	resp, err := http.Get("https://auth.example.com/.well-known/oauth-authorization-server")
//	var metadata wellknown.AuthorizationServerMetadata
//	json.NewDecoder(resp.Body).Decode(&metadata)
//
//	// Now use discovered endpoints
//	authURL := metadata.AuthorizationEndpoint
//	tokenURL := metadata.TokenEndpoint
//
// # Protected Resource Metadata (RFC 9728 - MCP)
//
// Endpoint: /.well-known/oauth-protected-resource
//
// Required for Model Context Protocol (MCP) compliance:
//
//	// Example response
//	{
//	    "resource": "https://api.example.com",
//	    "authorization_servers": ["https://auth.example.com"],
//	    "scopes": ["openid", "profile", "email"],
//	    "bearer_methods_supported": ["header"]
//	}
//
// Tells clients which authorization servers can issue tokens for this resource.
//
// # OpenID Connect Discovery
//
// Endpoint: /.well-known/openid-configuration
//
//	// Example response (superset of OAuth2 metadata)
//	{
//	    "issuer": "https://auth.example.com",
//	    "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
//	    "token_endpoint": "https://auth.example.com/api/oauth2/token",
//	    "userinfo_endpoint": "https://auth.example.com/api/oauth2/userinfo",
//	    "jwks_uri": "https://auth.example.com/api/oauth2/jwks",
//	    "scopes_supported": ["openid", "profile", "email"],
//	    "response_types_supported": ["code"],
//	    "subject_types_supported": ["public"],
//	    "id_token_signing_alg_values_supported": ["HS256"],
//	    ...
//	}
//
// # JWKS Endpoint
//
// Endpoints: /.well-known/jwks.json and /jwks
//
//	// Example response
//	{
//	    "keys": [
//	        {
//	            "kty": "RSA",
//	            "use": "sig",
//	            "kid": "key-2024-01",
//	            "alg": "RS256",
//	            "n": "0vx7agoebGcQSuuPiLJXZpt...",
//	            "e": "AQAB"
//	        }
//	    ]
//	}
//
// Clients use this to verify JWT signatures:
//
//	// Client-side JWT verification
//	jwksResp, _ := http.Get("https://auth.example.com/.well-known/jwks.json")
//	var jwks jwks.JWKS
//	json.NewDecoder(jwksResp.Body).Decode(&jwks)
//
//	// Find key by kid from JWT header
//	for _, key := range jwks.Keys {
//	    if key.Kid == tokenKid {
//	        publicKey := key.ToPublicKey()
//	        // Verify JWT with public key
//	    }
//	}
//
// # Production Example
//
//	package main
//
//	import (
//	    "log"
//	    "net/http"
//	    "os"
//
//	    "github.com/tendant/simple-idm/pkg/wellknown"
//	    "github.com/tendant/simple-idm/pkg/jwks"
//	    "github.com/go-chi/chi/v5"
//	    "github.com/go-chi/chi/v5/middleware"
//	)
//
//	func main() {
//	    // Load configuration from environment
//	    baseURL := os.Getenv("BASE_URL")  // https://auth.example.com
//
//	    // Setup JWKS
//	    jwksService, err := jwks.NewJWKSServiceWithInMemoryStorage()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Configure well-known endpoints
//	    config := wellknown.Config{
//	        ResourceURI:            baseURL,
//	        AuthorizationServerURI: baseURL,
//	        BaseURL:                baseURL,
//	        Scopes:                 []string{"openid", "profile", "email", "api.read", "api.write"},
//	        ResourceDocumentation:  baseURL + "/docs",
//	    }
//
//	    // Create handler with JWKS
//	    wellknownHandler := wellknown.NewHandler(config,
//	        wellknown.WithJWKSService(jwksService),
//	    )
//
//	    // Setup router
//	    r := chi.NewRouter()
//	    r.Use(middleware.Logger)
//	    r.Use(middleware.Recoverer)
//
//	    // Register well-known endpoints
//	    wellknownHandler.RegisterRoutesWithPrefix(func(pattern string, h http.HandlerFunc) {
//	        r.Get(pattern, h)
//	    })
//
//	    // Your OAuth2/OIDC endpoints
//	    r.Get("/oauth2/authorize", authorizeHandler)
//	    r.Post("/api/oauth2/token", tokenHandler)
//	    r.Get("/api/oauth2/userinfo", userinfoHandler)
//
//	    log.Printf("Server starting on :8080")
//	    log.Printf("Discovery: %s/.well-known/oauth-authorization-server", baseURL)
//	    http.ListenAndServe(":8080", r)
//	}
//
// # Client Integration Examples
//
// ## JavaScript/TypeScript
//
//	// Auto-discover OAuth2 configuration
//	async function discoverOAuth2Config(issuer: string) {
//	    const response = await fetch(`${issuer}/.well-known/oauth-authorization-server`);
//	    const config = await response.json();
//
//	    return {
//	        authorizationEndpoint: config.authorization_endpoint,
//	        tokenEndpoint: config.token_endpoint,
//	        jwksUri: config.jwks_uri,
//	        scopes: config.scopes_supported,
//	    };
//	}
//
//	const config = await discoverOAuth2Config('https://auth.example.com');
//	// Use config.authorizationEndpoint for OAuth2 flow
//
// ## Go Client
//
//	import "encoding/json"
//
//	func discoverOIDC(issuer string) (*wellknown.AuthorizationServerMetadata, error) {
//	    resp, err := http.Get(issuer + "/.well-known/openid-configuration")
//	    if err != nil {
//	        return nil, err
//	    }
//	    defer resp.Body.Close()
//
//	    var metadata wellknown.AuthorizationServerMetadata
//	    err = json.NewDecoder(resp.Body).Decode(&metadata)
//	    return &metadata, err
//	}
//
// ## Python
//
//	import requests
//
//	def discover_oidc(issuer):
//	    response = requests.get(f"{issuer}/.well-known/openid-configuration")
//	    return response.json()
//
//	config = discover_oidc("https://auth.example.com")
//	auth_endpoint = config["authorization_endpoint"]
//
// # HTTP Response Headers
//
// All endpoints return these headers:
//   - Content-Type: application/json
//   - Cache-Control: public, max-age=3600 (cache for 1 hour)
//   - Access-Control-Allow-Origin: * (CORS enabled)
//
// Cache headers are important because:
//   - Reduces server load
//   - Configuration rarely changes
//   - Improves client performance
//
// # Security Considerations
//
//  1. **HTTPS Only**: Always serve well-known endpoints over HTTPS in production
//  2. **Issuer Validation**: Clients must validate the issuer matches expected value
//  3. **CORS**: Enabled for browser-based clients (safe for public metadata)
//  4. **Cache TTL**: 1-hour cache means config changes take time to propagate
//  5. **JWKS Endpoint**: Must be protected from DoS (consider rate limiting)
//
// # Standards Compliance
//
//   - RFC 8414: OAuth 2.0 Authorization Server Metadata
//   - RFC 9728: OAuth 2.0 Protected Resource Metadata
//   - OpenID Connect Discovery 1.0
//   - Model Context Protocol (MCP) requirements
//   - PKCE (RFC 7636) support indicated via code_challenge_methods_supported
//
// # Testing
//
//	import (
//	    "net/http/httptest"
//	    "testing"
//	)
//
//	func TestWellKnownEndpoints(t *testing.T) {
//	    config := wellknown.Config{
//	        ResourceURI:            "https://test.example.com",
//	        AuthorizationServerURI: "https://test.example.com",
//	        BaseURL:                "https://test.example.com",
//	        Scopes:                 []string{"openid", "profile"},
//	    }
//
//	    handler := wellknown.NewHandler(config)
//
//	    // Test authorization server metadata
//	    req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
//	    w := httptest.NewRecorder()
//	    handler.AuthorizationServerMetadata(w, req)
//
//	    if w.Code != 200 {
//	        t.Errorf("Expected 200, got %d", w.Code)
//	    }
//
//	    // Verify JSON response
//	    var metadata wellknown.AuthorizationServerMetadata
//	    json.NewDecoder(w.Body).Decode(&metadata)
//
//	    if metadata.Issuer != config.AuthorizationServerURI {
//	        t.Errorf("Issuer mismatch")
//	    }
//	}
//
// # Best Practices
//
//  1. **Use Environment Variables** for URLs (different per environment)
//  2. **Include All Scopes** your server actually supports
//  3. **Keep Consistent** endpoint paths with OAuth2/OIDC standards
//  4. **Monitor Access** to well-known endpoints (high traffic = many clients)
//  5. **Version Carefully** as changes affect all clients
//
// # Troubleshooting
//
// **"JWKS endpoint not available"**: JWKSService not configured, use WithJWKSService option
//
// **405 Method Not Allowed**: All endpoints only accept GET requests
//
// **Clients can't discover**: Verify BaseURL is accessible and HTTPS cert is valid
//
// **Cache not updating**: Wait 1 hour or clear client cache manually
//
// # Zero Internal Dependencies
//
// This package only depends on:
//   - Go standard library (net/http, encoding/json)
//   - Simple-idm's pkg/jwks (optional, only for JWKS endpoint)
//
// Can be used standalone with any OAuth2/OIDC server implementation.
package wellknown
