package oauth2client

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
			return false
		}
	}
	return true
}
