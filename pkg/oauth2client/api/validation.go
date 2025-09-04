package api

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// RFC 7591 validation rules for OAuth2 Dynamic Client Registration

var (
	// Valid URI schemes for redirect URIs
	validRedirectSchemes = map[string]bool{
		"https":         true,
		"http":          true, // Only for localhost in development
		"custom-scheme": true, // For mobile apps
		"urn":           true, // For URN-based schemes
	}

	// Valid grant types according to RFC 6749 and extensions
	validGrantTypes = map[string]bool{
		"authorization_code": true,
		"implicit":           true,
		"password":           true,
		"client_credentials": true,
		"refresh_token":      true,
		"urn:ietf:params:oauth:grant-type:jwt-bearer":   true,
		"urn:ietf:params:oauth:grant-type:saml2-bearer": true,
	}

	// Valid response types according to RFC 6749 and OIDC
	validResponseTypes = map[string]bool{
		"code":                true,
		"token":               true,
		"id_token":            true,
		"code token":          true,
		"code id_token":       true,
		"token id_token":      true,
		"code token id_token": true,
		"none":                true,
	}

	// Valid token endpoint authentication methods
	validTokenEndpointAuthMethods = map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"client_secret_jwt":   true,
		"private_key_jwt":     true,
		"none":                true,
	}

	// Valid client types
	validClientTypes = map[string]bool{
		"confidential": true,
		"public":       true,
	}

	// Email regex pattern (basic validation)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// Valid scopes (can be extended)
	validScopes = map[string]bool{
		"openid":         true,
		"profile":        true,
		"email":          true,
		"address":        true,
		"phone":          true,
		"offline_access": true,
	}
)

// ValidationError represents a client registration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(messages, "; "))
}

// ValidateClientRegistrationRequest validates a client registration request according to RFC 7591
func ValidateClientRegistrationRequest(req *ClientRegistrationRequest) ValidationErrors {
	var errors ValidationErrors

	// Validate required fields
	if req.ClientName == "" {
		errors = append(errors, ValidationError{
			Field:   "client_name",
			Message: "client_name is required",
			Code:    "invalid_client_metadata",
		})
	}

	if len(req.RedirectUris) == 0 {
		errors = append(errors, ValidationError{
			Field:   "redirect_uris",
			Message: "redirect_uris is required and must not be empty",
			Code:    "invalid_client_metadata",
		})
	}

	// Validate redirect URIs
	for i, uri := range req.RedirectUris {
		if err := validateRedirectURI(uri); err != nil {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("redirect_uris[%d]", i),
				Message: err.Error(),
				Code:    "invalid_redirect_uri",
			})
		}
	}

	// Validate client type
	if req.ClientType != nil {
		clientType := req.ClientType.ToValue()
		if !validClientTypes[clientType] {
			errors = append(errors, ValidationError{
				Field:   "client_type",
				Message: fmt.Sprintf("invalid client_type: %s", clientType),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate grant types
	for i, gt := range req.GrantTypes {
		grantType := gt.ToValue()
		if !validGrantTypes[grantType] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("grant_types[%d]", i),
				Message: fmt.Sprintf("invalid grant_type: %s", grantType),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate response types
	for i, rt := range req.ResponseTypes {
		responseType := rt.ToValue()
		if !validResponseTypes[responseType] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("response_types[%d]", i),
				Message: fmt.Sprintf("invalid response_type: %s", responseType),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate token endpoint auth method
	if req.TokenEndpointAuthMethod != nil {
		authMethod := req.TokenEndpointAuthMethod.ToValue()
		if !validTokenEndpointAuthMethods[authMethod] {
			errors = append(errors, ValidationError{
				Field:   "token_endpoint_auth_method",
				Message: fmt.Sprintf("invalid token_endpoint_auth_method: %s", authMethod),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate URIs
	if req.ClientURI != nil {
		if err := validateURI(*req.ClientURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "client_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.LogoURI != nil {
		if err := validateURI(*req.LogoURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "logo_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.TosURI != nil {
		if err := validateURI(*req.TosURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "tos_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.PolicyURI != nil {
		if err := validateURI(*req.PolicyURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "policy_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.JwksURI != nil {
		if err := validateURI(*req.JwksURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "jwks_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate contacts (email addresses)
	for i, contact := range req.Contacts {
		if !emailRegex.MatchString(string(contact)) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("contacts[%d]", i),
				Message: fmt.Sprintf("invalid email address: %s", contact),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate scopes
	if req.Scope != nil {
		scopes := strings.Fields(*req.Scope)
		for _, scope := range scopes {
			if !validScopes[scope] {
				errors = append(errors, ValidationError{
					Field:   "scope",
					Message: fmt.Sprintf("invalid scope: %s", scope),
					Code:    "invalid_scope",
				})
			}
		}
	}

	// Validate consistency between grant types and response types
	if err := validateGrantTypeResponseTypeConsistency(req); err != nil {
		errors = append(errors, *err)
	}

	// Validate client type and auth method consistency
	if err := validateClientTypeAuthMethodConsistency(req); err != nil {
		errors = append(errors, *err)
	}

	return errors
}

// ValidateClientUpdateRequest validates a client update request
func ValidateClientUpdateRequest(req *ClientUpdateRequest) ValidationErrors {
	var errors ValidationErrors

	// Validate redirect URIs if provided
	for i, uri := range req.RedirectUris {
		if err := validateRedirectURI(uri); err != nil {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("redirect_uris[%d]", i),
				Message: err.Error(),
				Code:    "invalid_redirect_uri",
			})
		}
	}

	// Validate client type if provided
	if req.ClientType != nil {
		clientType := req.ClientType.ToValue()
		if !validClientTypes[clientType] {
			errors = append(errors, ValidationError{
				Field:   "client_type",
				Message: fmt.Sprintf("invalid client_type: %s", clientType),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate grant types if provided
	for i, gt := range req.GrantTypes {
		grantType := gt.ToValue()
		if !validGrantTypes[grantType] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("grant_types[%d]", i),
				Message: fmt.Sprintf("invalid grant_type: %s", grantType),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate response types if provided
	for i, rt := range req.ResponseTypes {
		responseType := rt.ToValue()
		if !validResponseTypes[responseType] {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("response_types[%d]", i),
				Message: fmt.Sprintf("invalid response_type: %s", responseType),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate token endpoint auth method if provided
	if req.TokenEndpointAuthMethod != nil {
		authMethod := req.TokenEndpointAuthMethod.ToValue()
		if !validTokenEndpointAuthMethods[authMethod] {
			errors = append(errors, ValidationError{
				Field:   "token_endpoint_auth_method",
				Message: fmt.Sprintf("invalid token_endpoint_auth_method: %s", authMethod),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate URIs if provided
	if req.ClientURI != nil {
		if err := validateURI(*req.ClientURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "client_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.LogoURI != nil {
		if err := validateURI(*req.LogoURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "logo_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.TosURI != nil {
		if err := validateURI(*req.TosURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "tos_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.PolicyURI != nil {
		if err := validateURI(*req.PolicyURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "policy_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	if req.JwksURI != nil {
		if err := validateURI(*req.JwksURI); err != nil {
			errors = append(errors, ValidationError{
				Field:   "jwks_uri",
				Message: err.Error(),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate contacts if provided
	for i, contact := range req.Contacts {
		if !emailRegex.MatchString(string(contact)) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("contacts[%d]", i),
				Message: fmt.Sprintf("invalid email address: %s", contact),
				Code:    "invalid_client_metadata",
			})
		}
	}

	// Validate scopes if provided
	if req.Scope != nil {
		scopes := strings.Fields(*req.Scope)
		for _, scope := range scopes {
			if !validScopes[scope] {
				errors = append(errors, ValidationError{
					Field:   "scope",
					Message: fmt.Sprintf("invalid scope: %s", scope),
					Code:    "invalid_scope",
				})
			}
		}
	}

	return errors
}

// validateRedirectURI validates a redirect URI according to RFC 6749 and RFC 7591
func validateRedirectURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("redirect URI cannot be empty")
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI format: %v", err)
	}

	// Check scheme
	if !validRedirectSchemes[parsedURI.Scheme] {
		return fmt.Errorf("invalid URI scheme: %s", parsedURI.Scheme)
	}

	// URI must not contain fragment
	if parsedURI.Fragment != "" {
		return fmt.Errorf("redirect URI must not contain fragment")
	}

	return nil
}

// validateURI validates a general URI
func validateURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("URI cannot be empty")
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI format: %v", err)
	}

	if parsedURI.Scheme == "" {
		return fmt.Errorf("URI must have a scheme")
	}

	if parsedURI.Scheme != "https" && parsedURI.Scheme != "http" {
		return fmt.Errorf("URI must use HTTP or HTTPS scheme")
	}

	return nil
}

// validateGrantTypeResponseTypeConsistency validates consistency between grant types and response types
func validateGrantTypeResponseTypeConsistency(req *ClientRegistrationRequest) *ValidationError {
	// If no grant types specified, use default
	grantTypes := []string{"authorization_code"}
	if len(req.GrantTypes) > 0 {
		grantTypes = make([]string, len(req.GrantTypes))
		for i, gt := range req.GrantTypes {
			grantTypes[i] = gt.ToValue()
		}
	}

	// If no response types specified, use default
	responseTypes := []string{"code"}
	if len(req.ResponseTypes) > 0 {
		responseTypes = make([]string, len(req.ResponseTypes))
		for i, rt := range req.ResponseTypes {
			responseTypes[i] = rt.ToValue()
		}
	}

	// Check consistency
	hasAuthCode := contains(grantTypes, "authorization_code")
	hasImplicit := contains(grantTypes, "implicit")

	hasCodeResponse := containsAny(responseTypes, []string{"code", "code token", "code id_token", "code token id_token"})
	hasTokenResponse := containsAny(responseTypes, []string{"token", "code token", "token id_token", "code token id_token"})

	if hasCodeResponse && !hasAuthCode {
		return &ValidationError{
			Field:   "grant_types",
			Message: "authorization_code grant type is required when using code response type",
			Code:    "invalid_client_metadata",
		}
	}

	if hasTokenResponse && !hasImplicit {
		return &ValidationError{
			Field:   "grant_types",
			Message: "implicit grant type is required when using token response type",
			Code:    "invalid_client_metadata",
		}
	}

	return nil
}

// validateClientTypeAuthMethodConsistency validates consistency between client type and auth method
func validateClientTypeAuthMethodConsistency(req *ClientRegistrationRequest) *ValidationError {
	clientType := "confidential"
	if req.ClientType != nil {
		clientType = req.ClientType.ToValue()
	}

	authMethod := "client_secret_basic"
	if req.TokenEndpointAuthMethod != nil {
		authMethod = req.TokenEndpointAuthMethod.ToValue()
	}

	// Public clients should use "none" auth method
	if clientType == "public" && authMethod != "none" {
		return &ValidationError{
			Field:   "token_endpoint_auth_method",
			Message: "public clients must use 'none' as token_endpoint_auth_method",
			Code:    "invalid_client_metadata",
		}
	}

	// Confidential clients should not use "none" auth method
	if clientType == "confidential" && authMethod == "none" {
		return &ValidationError{
			Field:   "token_endpoint_auth_method",
			Message: "confidential clients cannot use 'none' as token_endpoint_auth_method",
			Code:    "invalid_client_metadata",
		}
	}

	return nil
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsAny(slice []string, items []string) bool {
	for _, s := range slice {
		for _, item := range items {
			if s == item {
				return true
			}
		}
	}
	return false
}
