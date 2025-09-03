package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Handler provides HTTP handlers for well-known endpoints
type Handler struct {
	config Config
}

// NewHandler creates a new well-known endpoints handler
func NewHandler(config Config) *Handler {
	return &Handler{
		config: config,
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

// RegisterRoutes registers all well-known endpoint routes with the provided mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", h.OpenIDConfiguration)
}

// RegisterRoutesWithPrefix registers all well-known endpoint routes with a custom handler function
// This is useful when you need to integrate with existing routing systems
func (h *Handler) RegisterRoutesWithPrefix(registerFunc func(pattern string, handler http.HandlerFunc)) {
	registerFunc("/.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	registerFunc("/.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	registerFunc("/.well-known/openid-configuration", h.OpenIDConfiguration)
}
