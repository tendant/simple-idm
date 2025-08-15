package oauth2client

import (
	"context"
	"fmt"
	"strings"
)

// ClientService provides methods for managing OAuth2 clients
type ClientService struct {
	repository OAuth2ClientRepository
}

// NewClientService creates a new client service with the provided repository
func NewClientService(repository OAuth2ClientRepository) *ClientService {
	return &ClientService{
		repository: repository,
	}
}

// GetClient retrieves a client by client ID
func (s *ClientService) GetClient(clientID string) (*OAuth2Client, error) {
	ctx := context.Background()
	return s.repository.GetClient(ctx, clientID)
}

// ValidateClientCredentials validates client ID and secret
func (s *ClientService) ValidateClientCredentials(clientID, clientSecret string) (*OAuth2Client, error) {
	ctx := context.Background()
	return s.repository.ValidateClientCredentials(ctx, clientID, clientSecret)
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
	ctx := context.Background()
	clients, err := s.repository.ListClients(ctx)
	if err != nil {
		return make(map[string]*OAuth2Client)
	}

	// Convert slice to map for backward compatibility
	clientMap := make(map[string]*OAuth2Client)
	for _, client := range clients {
		clientMap[client.ClientID] = client
	}

	return clientMap
}
