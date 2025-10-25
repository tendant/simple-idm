package oauth2client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileOAuth2ClientRepository implements OAuth2ClientRepository using file-based storage
type FileOAuth2ClientRepository struct {
	dataDir string
	clients map[string]*OAuth2ClientEntity
	mutex   sync.RWMutex
}

// NewFileOAuth2ClientRepository creates a new file-based OAuth2 client repository
func NewFileOAuth2ClientRepository(dataDir string) (*FileOAuth2ClientRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileOAuth2ClientRepository{
		dataDir: dataDir,
		clients: make(map[string]*OAuth2ClientEntity),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// GetClient retrieves an OAuth2 client by client ID
func (r *FileOAuth2ClientRepository) GetClient(ctx context.Context, clientID string) (*OAuth2Client, error) {
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
func (r *FileOAuth2ClientRepository) CreateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
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

	// Persist to file
	if err := r.save(); err != nil {
		// Rollback on error
		delete(r.clients, client.ClientID)
		return nil, fmt.Errorf("failed to save: %w", err)
	}

	return entity.OAuth2Client, nil
}

// UpdateClient updates an existing OAuth2 client and returns the updated client
func (r *FileOAuth2ClientRepository) UpdateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
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

	// Persist to file
	if err := r.save(); err != nil {
		return nil, fmt.Errorf("failed to save: %w", err)
	}

	return entity.OAuth2Client, nil
}

// DeleteClient removes an OAuth2 client by client ID
func (r *FileOAuth2ClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.clients[clientID]; !exists {
		return fmt.Errorf("client not found: %s", clientID)
	}

	delete(r.clients, clientID)

	// Persist to file
	return r.save()
}

// ListClients returns all registered OAuth2 clients
func (r *FileOAuth2ClientRepository) ListClients(ctx context.Context) ([]*OAuth2Client, error) {
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
func (r *FileOAuth2ClientRepository) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	entity, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	if !entity.IsActive {
		return nil, fmt.Errorf("client is inactive: %s", clientID)
	}

	if entity.ClientSecret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	// Update last used time
	now := time.Now()
	entity.LastUsedAt = &now

	return entity.OAuth2Client, nil
}

// ClientExists checks if a client with the given ID exists
func (r *FileOAuth2ClientRepository) ClientExists(ctx context.Context, clientID string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, exists := r.clients[clientID]
	return exists, nil
}

// GetClientsByRedirectURI finds clients that have the specified redirect URI
func (r *FileOAuth2ClientRepository) GetClientsByRedirectURI(ctx context.Context, redirectURI string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var results []*OAuth2Client
	for _, entity := range r.clients {
		if !entity.IsActive {
			continue
		}

		for _, uri := range entity.RedirectURIs {
			if uri == redirectURI {
				results = append(results, entity.OAuth2Client)
				break
			}
		}
	}

	return results, nil
}

// GetClientsByScope finds clients that support the specified scope
func (r *FileOAuth2ClientRepository) GetClientsByScope(ctx context.Context, scope string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var results []*OAuth2Client
	for _, entity := range r.clients {
		if !entity.IsActive {
			continue
		}

		for _, s := range entity.Scopes {
			if strings.Contains(s, scope) {
				results = append(results, entity.OAuth2Client)
				break
			}
		}
	}

	return results, nil
}

// GetClientCount returns the total number of registered clients
func (r *FileOAuth2ClientRepository) GetClientCount(ctx context.Context) (int64, error) {
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
func (r *FileOAuth2ClientRepository) GetClientsByType(ctx context.Context, clientType string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var results []*OAuth2Client
	for _, entity := range r.clients {
		if entity.IsActive && entity.ClientType == clientType {
			results = append(results, entity.OAuth2Client)
		}
	}

	return results, nil
}

// WithTx returns a new repository with the given transaction
// File-based implementation doesn't support transactions, returns self
func (r *FileOAuth2ClientRepository) WithTx(tx interface{}) OAuth2ClientRepository {
	// File-based storage doesn't support transactions
	// Return self to maintain interface compatibility
	return r
}

// load reads OAuth2 client data from file
func (r *FileOAuth2ClientRepository) load() error {
	filePath := filepath.Join(r.dataDir, "oauth2_clients.json")

	// If file doesn't exist, start with empty map
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty map
	if len(data) == 0 {
		return nil
	}

	var clients []*OAuth2ClientEntity
	if err := json.Unmarshal(data, &clients); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to map
	r.clients = make(map[string]*OAuth2ClientEntity)
	for _, client := range clients {
		r.clients[client.ClientID] = client
	}

	return nil
}

// save writes OAuth2 client data to file atomically
func (r *FileOAuth2ClientRepository) save() error {
	// Convert map to slice
	clients := make([]*OAuth2ClientEntity, 0, len(r.clients))
	for _, client := range r.clients {
		clients = append(clients, client)
	}

	data, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "oauth2_clients.json.tmp")
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "oauth2_clients.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
