package oauth2client

import (
	"fmt"
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

// DefaultClients contains hardcoded OAuth2 clients for testing
var DefaultClients = map[string]*OAuth2Client{
	"golang_app": {
		ClientID:      "golang_app",
		ClientSecret:  "BfCGGjEvIgD5EnnF3Q5EobrW95wK0tOK",
		ClientName:    "Golang Demo App",
		RedirectURIs:  []string{"http://localhost:8182/demo/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile", "email"},
		ClientType:    "confidential",
	},
}

// GetClient retrieves a client by client ID
func GetClient(clientID string) (*OAuth2Client, error) {
	client, exists := DefaultClients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	return client, nil
}

// ValidateClientCredentials validates client ID and secret
func ValidateClientCredentials(clientID, clientSecret string) (*OAuth2Client, error) {
	client, err := GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}
