package oauth2client

import (
	"fmt"
	"strings"
)

// ClientService provides methods for managing OAuth2 clients
type ClientService struct {
	clients map[string]*OAuth2Client
}

// NewClientService creates a new client service with default clients
func NewClientService() *ClientService {
	return &ClientService{
		clients: DefaultClients,
	}
}

// GetClient retrieves a client by client ID
func (s *ClientService) GetClient(clientID string) (*OAuth2Client, error) {
	return GetClient(clientID)
}

// ValidateClientCredentials validates client ID and secret
func (s *ClientService) ValidateClientCredentials(clientID, clientSecret string) (*OAuth2Client, error) {
	return ValidateClientCredentials(clientID, clientSecret)
}

// ValidateAuthorizationRequest validates an OAuth2 authorization request
func (s *ClientService) ValidateAuthorizationRequest(clientID, redirectURI, responseType, scope string) (*OAuth2Client, error) {
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	// Validate redirect URI
	if !client.ValidateRedirectURI(redirectURI) {
		return nil, fmt.Errorf("invalid redirect_uri")
	}

	// Validate response type
	if !client.ValidateResponseType(responseType) {
		return nil, fmt.Errorf("unsupported response_type: %s", responseType)
	}

	// Validate scopes if provided
	if scope != "" {
		requestedScopes := strings.Split(scope, " ")
		if !client.ValidateScope(requestedScopes) {
			return nil, fmt.Errorf("invalid scope")
		}
	}

	return client, nil
}

// ListClients returns all registered clients (for admin purposes)
func (s *ClientService) ListClients() map[string]*OAuth2Client {
	return s.clients
}
