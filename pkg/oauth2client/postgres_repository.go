package oauth2client

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
	"github.com/tendant/simple-idm/pkg/oauth2client/oauth2clientdb"
)

// Constants for hardcoded OAuth2 values
const (
	DefaultResponseTypes = "code"
	DefaultGrantTypes    = "authorization_code"
)

// PostgresOAuth2ClientRepository implements OAuth2ClientRepository using PostgreSQL
type PostgresOAuth2ClientRepository struct {
	db        *pgxpool.Pool
	queries   *oauth2clientdb.Queries
	encryptor *EncryptionService
}

// NewPostgresOAuth2ClientRepository creates a new PostgreSQL OAuth2 client repository
func NewPostgresOAuth2ClientRepository(db *pgxpool.Pool, encryptionKey string) (*PostgresOAuth2ClientRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	encryptor, err := NewEncryptionService(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption service: %w", err)
	}

	return &PostgresOAuth2ClientRepository{
		db:        db,
		queries:   oauth2clientdb.New(db),
		encryptor: encryptor,
	}, nil
}

// GetClient retrieves an OAuth2 client by client ID
func (r *PostgresOAuth2ClientRepository) GetClient(ctx context.Context, clientID string) (*OAuth2Client, error) {
	row, err := r.queries.GetClient(ctx, clientID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("client not found: %s", clientID)
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return r.convertRowToClient(row.ID, row.ClientID, row.ClientSecretEncrypted, row.ClientName,
		row.ClientType, row.RequirePkce, row.Scopes, row.RedirectUris, row.CreatedAt.Time, row.UpdatedAt.Time)
}

// CreateClient creates a new OAuth2 client and returns the created client
func (r *PostgresOAuth2ClientRepository) CreateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	// Encrypt the client secret
	encryptedSecret, err := r.encryptor.Encrypt(client.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	// Start transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	txQueries := r.queries.WithTx(tx)

	// Create the client
	createResult, err := txQueries.CreateClient(ctx, oauth2clientdb.CreateClientParams{
		ClientID:              client.ClientID,
		ClientSecretEncrypted: encryptedSecret,
		ClientName:            client.ClientName,
		ClientType:            client.ClientType,
		RequirePkce:           client.RequirePKCE,
		Description:           sql.NullString{String: "", Valid: false}, // No description for now
		CreatedBy:             sql.NullString{String: "", Valid: false}, // No created_by for now
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	clientUUID := createResult.ID

	// Add scopes
	if err := r.addClientScopes(ctx, txQueries, clientUUID, client.Scopes); err != nil {
		return nil, fmt.Errorf("failed to add client scopes: %w", err)
	}

	// Add redirect URIs
	if err := r.addClientRedirectURIs(ctx, txQueries, clientUUID, client.RedirectURIs); err != nil {
		return nil, fmt.Errorf("failed to add client redirect URIs: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return the created client by retrieving it from the database
	createdClient, err := r.GetClient(ctx, client.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve created client: %w", err)
	}

	return createdClient, nil
}

// UpdateClient updates an existing OAuth2 client and returns the updated client
func (r *PostgresOAuth2ClientRepository) UpdateClient(ctx context.Context, client *OAuth2Client) (*OAuth2Client, error) {
	// Encrypt the client secret
	encryptedSecret, err := r.encryptor.Encrypt(client.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	// Start transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	txQueries := r.queries.WithTx(tx)

	// Get client UUID first
	clientRow, err := txQueries.GetClient(ctx, client.ClientID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("client not found: %s", client.ClientID)
		}
		return nil, fmt.Errorf("failed to get client for update: %w", err)
	}

	clientUUID := clientRow.ID

	// Update the client
	err = txQueries.UpdateClient(ctx, oauth2clientdb.UpdateClientParams{
		ClientID:              client.ClientID,
		ClientSecretEncrypted: encryptedSecret,
		ClientName:            client.ClientName,
		ClientType:            client.ClientType,
		RequirePkce:           client.RequirePKCE,
		Description:           sql.NullString{String: "", Valid: false},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	// Clear and re-add scopes
	if err := txQueries.ClearClientScopes(ctx, clientUUID); err != nil {
		return nil, fmt.Errorf("failed to clear client scopes: %w", err)
	}
	if err := r.addClientScopes(ctx, txQueries, clientUUID, client.Scopes); err != nil {
		return nil, fmt.Errorf("failed to add client scopes: %w", err)
	}

	// Clear and re-add redirect URIs
	if err := txQueries.ClearClientRedirectURIs(ctx, clientUUID); err != nil {
		return nil, fmt.Errorf("failed to clear client redirect URIs: %w", err)
	}
	if err := r.addClientRedirectURIs(ctx, txQueries, clientUUID, client.RedirectURIs); err != nil {
		return nil, fmt.Errorf("failed to add client redirect URIs: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return the updated client by retrieving it from the database
	updatedClient, err := r.GetClient(ctx, client.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve updated client: %w", err)
	}

	return updatedClient, nil
}

// DeleteClient removes an OAuth2 client by client ID (soft delete)
func (r *PostgresOAuth2ClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	err := r.queries.DeleteClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// ListClients returns all registered OAuth2 clients
func (r *PostgresOAuth2ClientRepository) ListClients(ctx context.Context) ([]*OAuth2Client, error) {
	rows, err := r.queries.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}

	clients := make([]*OAuth2Client, 0, len(rows))
	for _, row := range rows {
		client, err := r.convertRowToClient(row.ID, row.ClientID, row.ClientSecretEncrypted,
			row.ClientName, row.ClientType, row.RequirePkce, row.Scopes, row.RedirectUris, row.CreatedAt.Time, row.UpdatedAt.Time)
		if err != nil {
			return nil, fmt.Errorf("failed to convert row to client: %w", err)
		}
		clients = append(clients, client)
	}

	return clients, nil
}

// ValidateClientCredentials validates client ID and secret, returns client if valid
func (r *PostgresOAuth2ClientRepository) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*OAuth2Client, error) {
	client, err := r.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Decrypt and compare the client secret
	decryptedSecret, err := r.encryptor.Decrypt(client.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	if decryptedSecret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// ClientExists checks if a client with the given ID exists
func (r *PostgresOAuth2ClientRepository) ClientExists(ctx context.Context, clientID string) (bool, error) {
	exists, err := r.queries.ClientExists(ctx, clientID)
	if err != nil {
		return false, fmt.Errorf("failed to check client existence: %w", err)
	}
	return exists, nil
}

// GetClientsByRedirectURI finds clients that have the specified redirect URI
func (r *PostgresOAuth2ClientRepository) GetClientsByRedirectURI(ctx context.Context, redirectURI string) ([]*OAuth2Client, error) {
	// This would require a custom query, but since it was removed from the simplified version,
	// we'll implement a basic version by listing all clients and filtering
	allClients, err := r.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	var matchingClients []*OAuth2Client
	for _, client := range allClients {
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				matchingClients = append(matchingClients, client)
				break
			}
		}
	}

	return matchingClients, nil
}

// GetClientsByScope finds clients that support the specified scope
func (r *PostgresOAuth2ClientRepository) GetClientsByScope(ctx context.Context, scope string) ([]*OAuth2Client, error) {
	// Similar to redirect URI, implement by filtering all clients
	allClients, err := r.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	var matchingClients []*OAuth2Client
	for _, client := range allClients {
		for _, clientScope := range client.Scopes {
			if clientScope == scope {
				matchingClients = append(matchingClients, client)
				break
			}
		}
	}

	return matchingClients, nil
}

// GetClientCount returns the total number of registered clients
func (r *PostgresOAuth2ClientRepository) GetClientCount(ctx context.Context) (int64, error) {
	count, err := r.queries.GetClientCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get client count: %w", err)
	}
	return count, nil
}

// GetClientsByType returns clients filtered by type (public/confidential)
func (r *PostgresOAuth2ClientRepository) GetClientsByType(ctx context.Context, clientType string) ([]*OAuth2Client, error) {
	// Filter all clients by type
	allClients, err := r.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	var matchingClients []*OAuth2Client
	for _, client := range allClients {
		if client.ClientType == clientType {
			matchingClients = append(matchingClients, client)
		}
	}

	return matchingClients, nil
}

// WithTx returns a new repository instance that uses the provided transaction
func (r *PostgresOAuth2ClientRepository) WithTx(tx interface{}) OAuth2ClientRepository {
	pgxTx, ok := tx.(pgx.Tx)
	if !ok {
		// Return the same instance if tx is not a pgx.Tx
		return r
	}

	return &PostgresOAuth2ClientRepository{
		db:        r.db,
		queries:   r.queries.WithTx(pgxTx),
		encryptor: r.encryptor,
	}
}

// Helper methods

func (r *PostgresOAuth2ClientRepository) convertRowToClient(id uuid.UUID, clientID, encryptedSecret, clientName, clientType string, requirePKCE bool, scopesInterface, redirectURIsInterface interface{}, createdAt, updatedAt time.Time) (*OAuth2Client, error) {
	// Convert scopes from interface{} to []string
	scopes := r.convertInterfaceToStringSlice(scopesInterface)

	// Convert redirect URIs from interface{} to []string
	redirectURIs := r.convertInterfaceToStringSlice(redirectURIsInterface)

	return &OAuth2Client{
		ClientID:      clientID,
		ClientSecret:  encryptedSecret, // Store encrypted secret - will be decrypted only when needed
		ClientName:    clientName,
		RedirectURIs:  redirectURIs,
		ResponseTypes: []string{DefaultResponseTypes}, // Hardcoded
		GrantTypes:    []string{DefaultGrantTypes},    // Hardcoded
		Scopes:        scopes,
		ClientType:    clientType,
		RequirePKCE:   requirePKCE,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		CreatedBy:     "", // TODO: Add created_by support if needed
	}, nil
}

func (r *PostgresOAuth2ClientRepository) convertInterfaceToStringSlice(data interface{}) []string {
	if data == nil {
		return []string{}
	}

	// Handle pq.StringArray (PostgreSQL array type)
	if arr, ok := data.(pq.StringArray); ok {
		return []string(arr)
	}

	// Handle []string
	if arr, ok := data.([]string); ok {
		return arr
	}

	// Handle []interface{}
	if arr, ok := data.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	return []string{}
}

func (r *PostgresOAuth2ClientRepository) addClientScopes(ctx context.Context, queries *oauth2clientdb.Queries, clientID uuid.UUID, scopes []string) error {
	// Get all available scopes
	allScopes, err := queries.GetAllScopes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get all scopes: %w", err)
	}

	// Create a map for quick lookup
	scopeMap := make(map[string]uuid.UUID)
	for _, scope := range allScopes {
		scopeMap[scope.Name] = scope.ID
	}

	// Add each scope
	for _, scopeName := range scopes {
		if scopeID, exists := scopeMap[scopeName]; exists {
			err := queries.AddClientScope(ctx, oauth2clientdb.AddClientScopeParams{
				ClientID: clientID,
				ScopeID:  scopeID,
			})
			if err != nil {
				return fmt.Errorf("failed to add scope %s: %w", scopeName, err)
			}
		}
		// Ignore scopes that don't exist in the database
	}

	return nil
}

func (r *PostgresOAuth2ClientRepository) addClientRedirectURIs(ctx context.Context, queries *oauth2clientdb.Queries, clientID uuid.UUID, redirectURIs []string) error {
	for _, uri := range redirectURIs {
		err := queries.AddClientRedirectURI(ctx, oauth2clientdb.AddClientRedirectURIParams{
			ClientID:    clientID,
			RedirectUri: uri,
		})
		if err != nil {
			return fmt.Errorf("failed to add redirect URI %s: %w", uri, err)
		}
	}
	return nil
}
