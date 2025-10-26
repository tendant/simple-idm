package oauth2client

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// EnvOAuth2ClientRepository loads OAuth2 clients from environment variables
// This is a read-only repository that doesn't support dynamic client registration
// Perfect for small deployments with a handful of known clients
type EnvOAuth2ClientRepository struct {
	clients map[string]*OAuth2Client
	mutex   sync.RWMutex
}

// NewEnvOAuth2ClientRepository creates a repository from environment variables
// Environment variable format:
//   OAUTH2_CLIENTS=client1,client2
//   OAUTH2_CLIENT_CLIENT1_ID=my_client_id
//   OAUTH2_CLIENT_CLIENT1_SECRET=my_secret
//   OAUTH2_CLIENT_CLIENT1_NAME=My App
//   OAUTH2_CLIENT_CLIENT1_REDIRECT_URIS=https://app.example.com/callback,https://app.example.com/callback2
//   OAUTH2_CLIENT_CLIENT1_SCOPES=openid profile email
func NewEnvOAuth2ClientRepository() (*EnvOAuth2ClientRepository, error) {
	repo := &EnvOAuth2ClientRepository{
		clients: make(map[string]*OAuth2Client),
	}

	if err := repo.loadFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load OAuth2 clients from environment: %w", err)
	}

	return repo, nil
}

func (r *EnvOAuth2ClientRepository) loadFromEnv() error {
	// Get list of client names from OAUTH2_CLIENTS
	clientList := os.Getenv("OAUTH2_CLIENTS")
	if clientList == "" {
		// No clients configured - this is OK for testing
		return nil
	}

	clientNames := strings.Split(clientList, ",")

	for _, name := range clientNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		prefix := fmt.Sprintf("OAUTH2_CLIENT_%s_", strings.ToUpper(name))

		client := &OAuth2Client{
			ClientID:      os.Getenv(prefix + "ID"),
			ClientSecret:  os.Getenv(prefix + "SECRET"),
			ClientName:    getEnvOrDefault(prefix+"NAME", name),
			ClientType:    getEnvOrDefault(prefix+"TYPE", "confidential"),
			RedirectURIs:  parseCommaSeparatedList(os.Getenv(prefix + "REDIRECT_URIS")),
			Scopes:        parseCommaSeparatedList(getEnvOrDefault(prefix+"SCOPES", "openid profile email")),
			ResponseTypes: []string{"code"},                // Standard authorization code flow
			GrantTypes:    []string{"authorization_code"}, // Standard authorization code grant
			RequirePKCE:   false,                          // PKCE optional for environment clients
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			CreatedBy:     "environment",
		}

		// Validate required fields
		if client.ClientID == "" {
			return fmt.Errorf("client %s missing required field: ID (set %sID)", name, prefix)
		}
		if client.ClientSecret == "" {
			return fmt.Errorf("client %s missing required field: SECRET (set %sSECRET)", name, prefix)
		}
		if len(client.RedirectURIs) == 0 {
			return fmt.Errorf("client %s missing required field: REDIRECT_URIS (set %sREDIRECT_URIS)", name, prefix)
		}

		r.clients[client.ClientID] = client
	}

	return nil
}

// Helper to get environment variable or default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Helper to parse comma-separated list from environment variable
func parseCommaSeparatedList(value string) []string {
	if value == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetClient retrieves an OAuth2 client by client ID
func (r *EnvOAuth2ClientRepository) GetClient(ctx context.Context, clientID string) (*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	client, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}

	return client, nil
}

// CreateClient is not supported for environment-based repository (read-only)
func (r *EnvOAuth2ClientRepository) CreateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	return nil, fmt.Errorf("CreateClient not supported for environment-based repository (read-only)")
}

// UpdateClient is not supported for environment-based repository (read-only)
func (r *EnvOAuth2ClientRepository) UpdateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	return nil, fmt.Errorf("UpdateClient not supported for environment-based repository (read-only)")
}

// DeleteClient is not supported for environment-based repository (read-only)
func (r *EnvOAuth2ClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	return fmt.Errorf("DeleteClient not supported for environment-based repository (read-only)")
}

// ListClients returns all registered OAuth2 clients from environment
func (r *EnvOAuth2ClientRepository) ListClients(ctx context.Context) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	clients := make([]*OAuth2Client, 0, len(r.clients))
	for _, client := range r.clients {
		clients = append(clients, client)
	}

	return clients, nil
}

// ValidateClientCredentials validates client ID and secret, returns client if valid
func (r *EnvOAuth2ClientRepository) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*OAuth2Client, error) {
	client, err := r.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// ClientExists checks if a client with the given ID exists
func (r *EnvOAuth2ClientRepository) ClientExists(ctx context.Context, clientID string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, exists := r.clients[clientID]
	return exists, nil
}

// GetClientCount returns the total number of registered clients from environment
func (r *EnvOAuth2ClientRepository) GetClientCount(ctx context.Context) (int64, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return int64(len(r.clients)), nil
}

// GetClientsByType returns clients filtered by type (public/confidential)
func (r *EnvOAuth2ClientRepository) GetClientsByType(ctx context.Context, clientType string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var filtered []*OAuth2Client
	for _, client := range r.clients {
		if client.ClientType == clientType {
			filtered = append(filtered, client)
		}
	}

	return filtered, nil
}

// GetClientsByRedirectURI finds clients that have the specified redirect URI
func (r *EnvOAuth2ClientRepository) GetClientsByRedirectURI(ctx context.Context, redirectURI string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var filtered []*OAuth2Client
	for _, client := range r.clients {
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				filtered = append(filtered, client)
				break
			}
		}
	}

	return filtered, nil
}

// GetClientsByScope finds clients that support the specified scope
func (r *EnvOAuth2ClientRepository) GetClientsByScope(ctx context.Context, scope string) ([]*OAuth2Client, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var filtered []*OAuth2Client
	for _, client := range r.clients {
		for _, s := range client.Scopes {
			if s == scope {
				filtered = append(filtered, client)
				break
			}
		}
	}

	return filtered, nil
}

// WithTx returns a new repository instance that uses the provided transaction
// For environment-based implementation, this returns the same instance since there are no transactions
func (r *EnvOAuth2ClientRepository) WithTx(tx interface{}) OAuth2ClientRepository {
	// Environment-based repository is read-only and stateless, no transaction support needed
	return r
}
