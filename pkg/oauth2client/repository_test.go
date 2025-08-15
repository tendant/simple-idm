package oauth2client

import (
	"context"
	"testing"
)

func TestInMemoryOAuth2ClientRepository_GetClient(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	// Test getting an existing client (from DefaultClients)
	client, err := repo.GetClient(ctx, "golang_app")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if client.ClientID != "golang_app" {
		t.Errorf("Expected client ID 'golang_app', got %s", client.ClientID)
	}

	if client.ClientName != "Golang Demo App" {
		t.Errorf("Expected client name 'Golang Demo App', got %s", client.ClientName)
	}

	// Test getting a non-existent client
	_, err = repo.GetClient(ctx, "non_existent")
	if err == nil {
		t.Error("Expected error for non-existent client, got nil")
	}
}

func TestInMemoryOAuth2ClientRepository_CreateClient(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	newClient := &OAuth2Client{
		ClientID:      "test_client",
		ClientSecret:  "test_secret",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		ClientType:    "confidential",
	}

	// Test creating a new client
	err := repo.CreateClient(ctx, newClient)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify the client was created
	retrievedClient, err := repo.GetClient(ctx, "test_client")
	if err != nil {
		t.Fatalf("Expected no error retrieving created client, got %v", err)
	}

	if retrievedClient.ClientID != newClient.ClientID {
		t.Errorf("Expected client ID %s, got %s", newClient.ClientID, retrievedClient.ClientID)
	}

	// Test creating a client with duplicate ID
	err = repo.CreateClient(ctx, newClient)
	if err == nil {
		t.Error("Expected error for duplicate client ID, got nil")
	}
}

func TestInMemoryOAuth2ClientRepository_ValidateClientCredentials(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	// Test valid credentials
	client, err := repo.ValidateClientCredentials(ctx, "golang_app", "BfCGGjEvIgD5EnnF3Q5EobrW95wK0tOK")
	if err != nil {
		t.Fatalf("Expected no error for valid credentials, got %v", err)
	}

	if client.ClientID != "golang_app" {
		t.Errorf("Expected client ID 'golang_app', got %s", client.ClientID)
	}

	// Test invalid credentials
	_, err = repo.ValidateClientCredentials(ctx, "golang_app", "wrong_secret")
	if err == nil {
		t.Error("Expected error for invalid credentials, got nil")
	}

	// Test non-existent client
	_, err = repo.ValidateClientCredentials(ctx, "non_existent", "any_secret")
	if err == nil {
		t.Error("Expected error for non-existent client, got nil")
	}
}

func TestInMemoryOAuth2ClientRepository_ListClients(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	clients, err := repo.ListClients(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should have at least the default client
	if len(clients) == 0 {
		t.Error("Expected at least one client, got none")
	}

	// Check if the default client is present
	found := false
	for _, client := range clients {
		if client.ClientID == "golang_app" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find default client 'golang_app' in list")
	}
}

func TestInMemoryOAuth2ClientRepository_UpdateClient(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	// Get the original client
	originalClient, err := repo.GetClient(ctx, "golang_app")
	if err != nil {
		t.Fatalf("Expected no error getting original client, got %v", err)
	}

	// Update the client
	updatedClient := &OAuth2Client{
		ClientID:      "golang_app",
		ClientSecret:  "new_secret",
		ClientName:    "Updated Golang Demo App",
		RedirectURIs:  []string{"http://localhost:8080/new-callback"},
		ResponseTypes: []string{"code", "token"},
		GrantTypes:    []string{"authorization_code", "implicit"},
		Scopes:        []string{"openid", "profile", "email"},
		ClientType:    "public",
	}

	err = repo.UpdateClient(ctx, updatedClient)
	if err != nil {
		t.Fatalf("Expected no error updating client, got %v", err)
	}

	// Verify the client was updated
	retrievedClient, err := repo.GetClient(ctx, "golang_app")
	if err != nil {
		t.Fatalf("Expected no error retrieving updated client, got %v", err)
	}

	if retrievedClient.ClientName != "Updated Golang Demo App" {
		t.Errorf("Expected updated client name 'Updated Golang Demo App', got %s", retrievedClient.ClientName)
	}

	if retrievedClient.ClientSecret != "new_secret" {
		t.Errorf("Expected updated client secret 'new_secret', got %s", retrievedClient.ClientSecret)
	}

	// Test updating non-existent client
	nonExistentClient := &OAuth2Client{
		ClientID: "non_existent",
	}
	err = repo.UpdateClient(ctx, nonExistentClient)
	if err == nil {
		t.Error("Expected error updating non-existent client, got nil")
	}

	// Restore original client for other tests
	repo.UpdateClient(ctx, originalClient)
}

func TestInMemoryOAuth2ClientRepository_DeleteClient(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	// Create a test client to delete
	testClient := &OAuth2Client{
		ClientID:     "delete_test",
		ClientSecret: "secret",
		ClientName:   "Delete Test Client",
		ClientType:   "confidential",
	}

	err := repo.CreateClient(ctx, testClient)
	if err != nil {
		t.Fatalf("Expected no error creating test client, got %v", err)
	}

	// Delete the client
	err = repo.DeleteClient(ctx, "delete_test")
	if err != nil {
		t.Fatalf("Expected no error deleting client, got %v", err)
	}

	// Verify the client was deleted
	_, err = repo.GetClient(ctx, "delete_test")
	if err == nil {
		t.Error("Expected error getting deleted client, got nil")
	}

	// Test deleting non-existent client
	err = repo.DeleteClient(ctx, "non_existent")
	if err == nil {
		t.Error("Expected error deleting non-existent client, got nil")
	}
}

func TestInMemoryOAuth2ClientRepository_GetClientsByRedirectURI(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	clients, err := repo.GetClientsByRedirectURI(ctx, "http://localhost:8182/demo/callback")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(clients) == 0 {
		t.Error("Expected at least one client with the redirect URI, got none")
	}

	// Test with non-existent redirect URI
	clients, err = repo.GetClientsByRedirectURI(ctx, "http://nonexistent.com/callback")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(clients) != 0 {
		t.Errorf("Expected no clients with non-existent redirect URI, got %d", len(clients))
	}
}

func TestInMemoryOAuth2ClientRepository_GetClientsByScope(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	clients, err := repo.GetClientsByScope(ctx, "openid")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(clients) == 0 {
		t.Error("Expected at least one client with 'openid' scope, got none")
	}

	// Test with non-existent scope
	clients, err = repo.GetClientsByScope(ctx, "nonexistent_scope")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(clients) != 0 {
		t.Errorf("Expected no clients with non-existent scope, got %d", len(clients))
	}
}

func TestInMemoryOAuth2ClientRepository_GetClientCount(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	count, err := repo.GetClientCount(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count == 0 {
		t.Error("Expected at least one client, got count of 0")
	}
}

func TestInMemoryOAuth2ClientRepository_GetClientsByType(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	clients, err := repo.GetClientsByType(ctx, "confidential")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(clients) == 0 {
		t.Error("Expected at least one confidential client, got none")
	}

	// Verify all returned clients are confidential
	for _, client := range clients {
		if client.ClientType != "confidential" {
			t.Errorf("Expected all clients to be confidential, found %s", client.ClientType)
		}
	}
}

func TestInMemoryOAuth2ClientRepository_ClientExists(t *testing.T) {
	repo := NewInMemoryOAuth2ClientRepository()
	ctx := context.Background()

	// Test existing client
	exists, err := repo.ClientExists(ctx, "golang_app")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !exists {
		t.Error("Expected client to exist, got false")
	}

	// Test non-existent client
	exists, err = repo.ClientExists(ctx, "non_existent")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if exists {
		t.Error("Expected client to not exist, got true")
	}
}
