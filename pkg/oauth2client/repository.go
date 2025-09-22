package oauth2client

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// OAuth2ClientRepository defines the interface for OAuth2 client data access operations
type OAuth2ClientRepository interface {
	// Core CRUD operations

	// GetClient retrieves an OAuth2 client by client ID
	GetClient(ctx context.Context, clientID string) (*OAuth2Client, error)

	// CreateClient creates a new OAuth2 client and returns the created client
	CreateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error)

	// UpdateClient updates an existing OAuth2 client and returns the updated client
	UpdateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error)

	// DeleteClient removes an OAuth2 client by client ID
	DeleteClient(ctx context.Context, clientID string) error

	// ListClients returns all registered OAuth2 clients
	ListClients(ctx context.Context) ([]*OAuth2Client, error)

	// Validation and authentication operations

	// ValidateClientCredentials validates client ID and secret, returns client if valid
	ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*OAuth2Client, error)

	// ClientExists checks if a client with the given ID exists
	ClientExists(ctx context.Context, clientID string) (bool, error)

	// Query operations for OAuth2 flows

	// GetClientsByRedirectURI finds clients that have the specified redirect URI
	GetClientsByRedirectURI(ctx context.Context, redirectURI string) ([]*OAuth2Client, error)

	// GetClientsByScope finds clients that support the specified scope
	GetClientsByScope(ctx context.Context, scope string) ([]*OAuth2Client, error)

	// Administrative operations

	// GetClientCount returns the total number of registered clients
	GetClientCount(ctx context.Context) (int64, error)

	// GetClientsByType returns clients filtered by type (public/confidential)
	GetClientsByType(ctx context.Context, clientType string) ([]*OAuth2Client, error)

	// Transaction support for future database implementations

	// WithTx returns a new repository instance that uses the provided transaction
	// The tx parameter should be a database transaction (e.g., pgx.Tx for PostgreSQL)
	WithTx(tx interface{}) OAuth2ClientRepository
}

// OAuth2ClientEntity represents additional metadata that might be stored with clients
// This can be extended when moving to database storage
type OAuth2ClientEntity struct {
	*OAuth2Client
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string     // User/system that created the client
	LastUsedAt  *time.Time // Last time this client was used for authentication
	IsActive    bool       // Whether the client is currently active
	Description string     // Optional description of the client
}

// CreateClientParams represents parameters for creating a new OAuth2 client
type CreateClientParams struct {
	ClientID      string
	ClientSecret  string
	ClientName    string
	RedirectURIs  []string
	ResponseTypes []string
	GrantTypes    []string
	Scopes        []string
	ClientType    string
	Description   string
	CreatedBy     string
}

// UpdateClientParams represents parameters for updating an OAuth2 client
type UpdateClientParams struct {
	ClientID      string
	ClientSecret  *string // Pointer to allow nil (no update)
	ClientName    *string
	RedirectURIs  []string
	ResponseTypes []string
	GrantTypes    []string
	Scopes        []string
	ClientType    *string
	Description   *string
	IsActive      *bool
}

// ListClientsParams represents parameters for listing clients with filtering/pagination
type ListClientsParams struct {
	Limit      int32
	Offset     int32
	ClientType *string // Filter by client type
	IsActive   *bool   // Filter by active status
	CreatedBy  *string // Filter by creator
}

// InMemoryOAuth2ClientRepository implements OAuth2ClientRepository using in-memory storage
type InMemoryOAuth2ClientRepository struct {
	clients map[string]*OAuth2ClientEntity
	mutex   sync.RWMutex
}

// NewInMemoryOAuth2ClientRepository creates a new in-memory OAuth2 client repository
// Starts empty - clients should be added through the service layer
func NewInMemoryOAuth2ClientRepository() *InMemoryOAuth2ClientRepository {
	repo := &InMemoryOAuth2ClientRepository{
		clients: make(map[string]*OAuth2ClientEntity),
	}

	return repo
}

// GetClient retrieves an OAuth2 client by client ID
func (r *InMemoryOAuth2ClientRepository) GetClient(ctx context.Context, clientID string) (*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	entity, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	if !entity.IsActive {
		return nil, fmt.Errorf("client is inactive: %s", clientID)
	}

	return entity.OAuth2Client, nil
}

// CreateClient creates a new OAuth2 client and returns the created client
func (r *InMemoryOAuth2ClientRepository) CreateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.clients[client.ClientID]; exists {
		return nil, fmt.Errorf("client already exists: %s", client.ClientID)
	}

	now := time.Now()
	entity := &OAuth2ClientEntity{
		OAuth2Client: &OAuth2Client{
			ClientID:      client.ClientID,
			ClientSecret:  client.ClientSecret,
			ClientName:    client.ClientName,
			RedirectURIs:  make([]string, len(client.RedirectURIs)),
			ResponseTypes: make([]string, len(client.ResponseTypes)),
			GrantTypes:    make([]string, len(client.GrantTypes)),
			Scopes:        make([]string, len(client.Scopes)),
			ClientType:    client.ClientType,
		},
		CreatedAt: now,
		UpdatedAt: now,
		IsActive:  true,
	}

	// Deep copy slices
	copy(entity.RedirectURIs, client.RedirectURIs)
	copy(entity.ResponseTypes, client.ResponseTypes)
	copy(entity.GrantTypes, client.GrantTypes)
	copy(entity.Scopes, client.Scopes)

	r.clients[client.ClientID] = entity
	return entity.OAuth2Client, nil
}

// UpdateClient updates an existing OAuth2 client and returns the updated client
func (r *InMemoryOAuth2ClientRepository) UpdateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	entity, exists := r.clients[client.ClientID]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", client.ClientID)
	}

	// Update the client data
	entity.OAuth2Client = &OAuth2Client{
		ClientID:      client.ClientID,
		ClientSecret:  client.ClientSecret,
		ClientName:    client.ClientName,
		RedirectURIs:  make([]string, len(client.RedirectURIs)),
		ResponseTypes: make([]string, len(client.ResponseTypes)),
		GrantTypes:    make([]string, len(client.GrantTypes)),
		Scopes:        make([]string, len(client.Scopes)),
		ClientType:    client.ClientType,
	}

	// Deep copy slices
	copy(entity.RedirectURIs, client.RedirectURIs)
	copy(entity.ResponseTypes, client.ResponseTypes)
	copy(entity.GrantTypes, client.GrantTypes)
	copy(entity.Scopes, client.Scopes)

	entity.UpdatedAt = time.Now()

	return entity.OAuth2Client, nil
}

// DeleteClient removes an OAuth2 client by client ID
func (r *InMemoryOAuth2ClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.clients[clientID]; !exists {
		return fmt.Errorf("client not found: %s", clientID)
	}

	delete(r.clients, clientID)
	return nil
}

// ListClients returns all registered OAuth2 clients
func (r *InMemoryOAuth2ClientRepository) ListClients(ctx context.Context) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	clients := make([]*OAuth2Client, 0, len(r.clients))
	for _, entity := range r.clients {
		if entity.IsActive {
			clients = append(clients, entity.OAuth2Client)
		}
	}

	return clients, nil
}

// ValidateClientCredentials validates client ID and secret, returns client if valid
func (r *InMemoryOAuth2ClientRepository) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*OAuth2Client, error) {
	client, err := r.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	// Update last used timestamp
	r.mutex.Lock()
	if entity, exists := r.clients[clientID]; exists {
		now := time.Now()
		entity.LastUsedAt = &now
	}
	r.mutex.Unlock()

	return client, nil
}

// ClientExists checks if a client with the given ID exists
func (r *InMemoryOAuth2ClientRepository) ClientExists(ctx context.Context, clientID string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	entity, exists := r.clients[clientID]
	return exists && entity.IsActive, nil
}

// GetClientsByRedirectURI finds clients that have the specified redirect URI
func (r *InMemoryOAuth2ClientRepository) GetClientsByRedirectURI(ctx context.Context, redirectURI string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var matchingClients []*OAuth2Client
	for _, entity := range r.clients {
		if !entity.IsActive {
			continue
		}

		for _, uri := range entity.RedirectURIs {
			if uri == redirectURI {
				matchingClients = append(matchingClients, entity.OAuth2Client)
				break
			}
		}
	}

	return matchingClients, nil
}

// GetClientsByScope finds clients that support the specified scope
func (r *InMemoryOAuth2ClientRepository) GetClientsByScope(ctx context.Context, scope string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var matchingClients []*OAuth2Client
	for _, entity := range r.clients {
		if !entity.IsActive {
			continue
		}

		for _, clientScope := range entity.Scopes {
			if clientScope == scope {
				matchingClients = append(matchingClients, entity.OAuth2Client)
				break
			}
		}
	}

	return matchingClients, nil
}

// GetClientCount returns the total number of registered clients
func (r *InMemoryOAuth2ClientRepository) GetClientCount(ctx context.Context) (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	count := int64(0)
	for _, entity := range r.clients {
		if entity.IsActive {
			count++
		}
	}

	return count, nil
}

// GetClientsByType returns clients filtered by type (public/confidential)
func (r *InMemoryOAuth2ClientRepository) GetClientsByType(ctx context.Context, clientType string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var matchingClients []*OAuth2Client
	for _, entity := range r.clients {
		if entity.IsActive && entity.ClientType == clientType {
			matchingClients = append(matchingClients, entity.OAuth2Client)
		}
	}

	return matchingClients, nil
}

// WithTx returns a new repository instance that uses the provided transaction
// For in-memory implementation, this returns the same instance since there are no transactions
func (r *InMemoryOAuth2ClientRepository) WithTx(tx interface{}) OAuth2ClientRepository {
	// For in-memory implementation, we don't support transactions
	// Return the same instance
	return r
}
