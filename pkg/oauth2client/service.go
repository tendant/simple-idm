package oauth2client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// CreateClient creates a new OAuth2 client and returns the created client
func (s *ClientService) CreateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	return s.repository.CreateClient(ctx, client)
}

// UpdateClient updates an existing OAuth2 client and returns the updated client
func (s *ClientService) UpdateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	return s.repository.UpdateClient(ctx, client)
}

// DeleteClient removes an OAuth2 client by client ID
func (s *ClientService) DeleteClient(ctx context.Context, clientID string) error {
	return s.repository.DeleteClient(ctx, clientID)
}

// ClientExists checks if a client with the given ID exists
func (s *ClientService) ClientExists(ctx context.Context, clientID string) (bool, error) {
	return s.repository.ClientExists(ctx, clientID)
}

// GetClientCount returns the total number of registered clients
func (s *ClientService) GetClientCount(ctx context.Context) (int64, error) {
	return s.repository.GetClientCount(ctx)
}

// GetClientsByType returns clients filtered by type (public/confidential)
func (s *ClientService) GetClientsByType(ctx context.Context, clientType string) ([]*OAuth2Client, error) {
	return s.repository.GetClientsByType(ctx, clientType)
}

// GetClientsByRedirectURI finds clients that have the specified redirect URI
func (s *ClientService) GetClientsByRedirectURI(ctx context.Context, redirectURI string) ([]*OAuth2Client, error) {
	return s.repository.GetClientsByRedirectURI(ctx, redirectURI)
}

// GetClientsByScope finds clients that support the specified scope
func (s *ClientService) GetClientsByScope(ctx context.Context, scope string) ([]*OAuth2Client, error) {
	return s.repository.GetClientsByScope(ctx, scope)
}

// GenerateClientSecret generates a new client secret
func (s *ClientService) GenerateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "secret_" + hex.EncodeToString(bytes), nil
}
