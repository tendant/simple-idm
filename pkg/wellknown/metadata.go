package wellknown

// ProtectedResourceMetadata represents the OAuth 2.0 Protected Resource Metadata
// as defined in RFC 9728: https://datatracker.ietf.org/doc/html/rfc9728
type ProtectedResourceMetadata struct {
	// REQUIRED: The resource identifier for the protected resource
	Resource string `json:"resource"`

	// REQUIRED: Array of authorization server identifiers that can issue tokens for this resource
	AuthorizationServers []string `json:"authorization_servers"`

	// OPTIONAL: Array of scope values that the resource server uses for access control
	Scopes []string `json:"scopes,omitempty"`

	// OPTIONAL: Array of methods supported for presenting bearer tokens
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// OPTIONAL: Array of resource parameters supported by the resource server
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// AuthorizationServerMetadata represents the OAuth 2.0 Authorization Server Metadata
// as defined in RFC 8414: https://datatracker.ietf.org/doc/html/rfc8414
type AuthorizationServerMetadata struct {
	// REQUIRED: The authorization server's issuer identifier
	Issuer string `json:"issuer"`

	// REQUIRED: URL of the authorization server's authorization endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// REQUIRED: URL of the authorization server's token endpoint
	TokenEndpoint string `json:"token_endpoint"`

	// OPTIONAL: URL of the authorization server's JWK Set document
	JwksURI string `json:"jwks_uri,omitempty"`

	// OPTIONAL: URL of the authorization server's Dynamic Client Registration endpoint
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// OPTIONAL: Array of scope values that the authorization server supports
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// OPTIONAL: Array of response_type values that the authorization server supports
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// OPTIONAL: Array of grant_type values that the authorization server supports
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// OPTIONAL: Array of client authentication methods supported by the token endpoint
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// REQUIRED for MCP: Array of PKCE code challenge methods supported
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	// OPTIONAL: Boolean indicating server support for the "resource" parameter
	ResourceParameterSupported bool `json:"resource_parameter_supported,omitempty"`
}

// Config holds configuration for well-known endpoints
type Config struct {
	// The canonical URI of this resource server (e.g., "https://localhost:4000")
	ResourceURI string

	// The URI of the authorization server (often same as ResourceURI for simple-idm)
	AuthorizationServerURI string

	// Base URL for constructing endpoint URLs
	BaseURL string

	// Supported scopes
	Scopes []string

	// Documentation URL for this resource server
	ResourceDocumentation string
}

// NewProtectedResourceMetadata creates a new ProtectedResourceMetadata instance
func NewProtectedResourceMetadata(config Config) *ProtectedResourceMetadata {
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &ProtectedResourceMetadata{
		Resource:               config.ResourceURI,
		AuthorizationServers:   []string{config.AuthorizationServerURI},
		Scopes:                 scopes,
		BearerMethodsSupported: []string{"header"}, // Authorization: Bearer header
		ResourceDocumentation:  config.ResourceDocumentation,
	}
}

// NewAuthorizationServerMetadata creates a new AuthorizationServerMetadata instance
func NewAuthorizationServerMetadata(config Config) *AuthorizationServerMetadata {
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &AuthorizationServerMetadata{
		Issuer:                            config.AuthorizationServerURI,
		AuthorizationEndpoint:             config.BaseURL + "/api/idm/oauth2/authorize",
		TokenEndpoint:                     config.BaseURL + "/api/idm/oauth2/token",
		JwksURI:                           config.BaseURL + "/api/idm/oauth2/jwks",
		ScopesSupported:                   scopes,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:     []string{"S256"}, // Required for MCP compliance
		ResourceParameterSupported:        true,             // Will be implemented in next phase
	}
}
