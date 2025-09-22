package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm/pkg/jwks"
)

// Handler provides HTTP handlers for well-known endpoints
type Handler struct {
	config      Config
	jwksService *jwks.JWKSService
}

// NewHandler creates a new well-known endpoints handler
func NewHandler(config Config, opts ...HandlerOption) *Handler {
	h := &Handler{
		config: config,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandlerOption configures the Handler
type HandlerOption func(*Handler)

// WithJWKSService configures the optional JWKS service
func WithJWKSService(js *jwks.JWKSService) HandlerOption {
	return func(h *Handler) {
		h.jwksService = js
	}
}

// ProtectedResourceMetadata handles GET /.well-known/oauth-protected-resource
// This endpoint is required by RFC 9728 for MCP compliance
func (h *Handler) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	slog.Info("Protected Resource Metadata request received", "method", r.Method, "path", r.URL.Path)

	// Only allow GET requests
	if r.Method != http.MethodGet {
		slog.Warn("Method not allowed for protected resource metadata", "method", r.Method)
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create the metadata
	metadata := NewProtectedResourceMetadata(h.config)

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Header().Set("Access-Control-Allow-Origin", "*")      // Allow CORS for discovery

	// Encode and send the response
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		slog.Error("Failed to encode protected resource metadata", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Info("Protected Resource Metadata response sent successfully",
		"resource", metadata.Resource,
		"authorization_servers", metadata.AuthorizationServers)
}

// AuthorizationServerMetadata handles GET /.well-known/oauth-authorization-server
// This endpoint is required by RFC 8414 for MCP compliance
func (h *Handler) AuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	slog.Info("Authorization Server Metadata request received", "method", r.Method, "path", r.URL.Path)

	// Only allow GET requests
	if r.Method != http.MethodGet {
		slog.Warn("Method not allowed for authorization server metadata", "method", r.Method)
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create the metadata
	metadata := NewAuthorizationServerMetadata(h.config)

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Header().Set("Access-Control-Allow-Origin", "*")      // Allow CORS for discovery

	// Encode and send the response
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		slog.Error("Failed to encode authorization server metadata", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Info("Authorization Server Metadata response sent successfully",
		"issuer", metadata.Issuer,
		"authorization_endpoint", metadata.AuthorizationEndpoint,
		"token_endpoint", metadata.TokenEndpoint)
}

// OpenIDConfiguration handles GET /.well-known/openid-configuration
// This endpoint provides OpenID Connect Discovery 1.0 compatibility
func (h *Handler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	slog.Info("OpenID Configuration request received", "method", r.Method, "path", r.URL.Path)

	// Only allow GET requests
	if r.Method != http.MethodGet {
		slog.Warn("Method not allowed for OpenID configuration", "method", r.Method)
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create the metadata (same as authorization server metadata for our purposes)
	metadata := NewAuthorizationServerMetadata(h.config)

	// Add OpenID Connect specific fields
	oidcMetadata := map[string]interface{}{
		"issuer":                                metadata.Issuer,
		"authorization_endpoint":                metadata.AuthorizationEndpoint,
		"token_endpoint":                        metadata.TokenEndpoint,
		"jwks_uri":                              metadata.JwksURI,
		"scopes_supported":                      metadata.ScopesSupported,
		"response_types_supported":              metadata.ResponseTypesSupported,
		"grant_types_supported":                 metadata.GrantTypesSupported,
		"token_endpoint_auth_methods_supported": metadata.TokenEndpointAuthMethodsSupported,
		"code_challenge_methods_supported":      metadata.CodeChallengeMethodsSupported,
		"resource_parameter_supported":          metadata.ResourceParameterSupported,
		// OpenID Connect specific fields
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"HS256"},
		"userinfo_endpoint":                     metadata.UserinfoEndpoint,
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Header().Set("Access-Control-Allow-Origin", "*")      // Allow CORS for discovery

	// Encode and send the response
	if err := json.NewEncoder(w).Encode(oidcMetadata); err != nil {
		slog.Error("Failed to encode OpenID configuration", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Info("OpenID Configuration response sent successfully",
		"issuer", metadata.Issuer)
}

// JWKS handles GET /.well-known/jwks.json and /jwks
// This endpoint provides the JSON Web Key Set for token verification
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	slog.Info("JWKS request received", "method", r.Method, "path", r.URL.Path)

	// Only allow GET requests
	if r.Method != http.MethodGet {
		slog.Warn("Method not allowed for JWKS", "method", r.Method)
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if JWKS service is configured
	if h.jwksService == nil {
		slog.Error("JWKS service not configured")
		http.Error(w, "JWKS endpoint not available", http.StatusNotImplemented)
		return
	}

	// Get JWKS from service
	jwks, err := (*h.jwksService).GetJWKS()
	if err != nil {
		slog.Error("Failed to get JWKS", "error", err)
		http.Error(w, "Failed to retrieve keys", http.StatusInternalServerError)
		return
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Header().Set("Access-Control-Allow-Origin", "*")      // Allow CORS for discovery

	// Encode and send the response
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		slog.Error("Failed to encode JWKS", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Info("JWKS request successful", "keys_count", len(jwks.Keys))
}

// RegisterRoutes registers all well-known endpoint routes with the provided mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", h.OpenIDConfiguration)
	mux.HandleFunc("/.well-known/jwks.json", h.JWKS)
	mux.HandleFunc("/jwks", h.JWKS)
}

// RegisterRoutesWithPrefix registers all well-known endpoint routes with a custom handler function
// This is useful when you need to integrate with existing routing systems
func (h *Handler) RegisterRoutesWithPrefix(registerFunc func(pattern string, handler http.HandlerFunc)) {
	registerFunc("/.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	registerFunc("/.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	registerFunc("/.well-known/openid-configuration", h.OpenIDConfiguration)
	registerFunc("/.well-known/jwks.json", h.JWKS)
	registerFunc("/jwks", h.JWKS)
}
