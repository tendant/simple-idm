package oauth2client

import (
	"log/slog"
	"time"
)

// OAuth2Client represents an OAuth2 client configuration
type OAuth2Client struct {
	ClientID      string
	ClientSecret  string
	ClientName    string
	RedirectURIs  []string
	ResponseTypes []string
	GrantTypes    []string
	Scopes        []string
	ClientType    string // "public" or "confidential"
	RequirePKCE   bool   // Whether this client requires PKCE
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CreatedBy     string
}

// ValidateRedirectURI checks if the provided redirect URI is allowed for this client
func (c *OAuth2Client) ValidateRedirectURI(redirectURI string) bool {
	for _, allowedURI := range c.RedirectURIs {
		if allowedURI == redirectURI {
			return true
		}
	}
	return false
}

// ValidateResponseType checks if the provided response type is allowed for this client
func (c *OAuth2Client) ValidateResponseType(responseType string) bool {
	for _, allowedType := range c.ResponseTypes {
		if allowedType == responseType {
			return true
		}
	}
	return false
}

// ValidateScope checks if the provided scopes are allowed for this client
func (c *OAuth2Client) ValidateScope(requestedScopes []string) bool {
	for _, requestedScope := range requestedScopes {
		found := false
		for _, allowedScope := range c.Scopes {
			if allowedScope == requestedScope {
				found = true
				break
			}
		}
		if !found {
			// Debug logging to understand validation failure
			slog.Error("Scope validation failed",
				"requested_scope", requestedScope,
				"allowed_scopes", c.Scopes,
				"all_requested", requestedScopes)
			return false
		}
	}
	return true
}
