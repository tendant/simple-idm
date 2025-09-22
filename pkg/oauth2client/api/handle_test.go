package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tendant/simple-idm/pkg/oauth2client"
)

func TestRegisterClient(t *testing.T) {
	// Create a mock client service
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	handle := NewHandle(clientService)

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Valid client registration",
			requestBody: ClientRegistrationRequest{
				ClientID:      "test-client-1",
				ClientName:    "Test Client",
				RedirectUris:  []string{"https://example.com/callback"},
				ClientType:    stringPtr("confidential"),
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
				Scope:         stringPtr("openid profile email"),
			},
			expectedStatus: 201,
		},
		{
			name: "Missing client name",
			requestBody: ClientRegistrationRequest{
				ClientID:     "test-client-2",
				RedirectUris: []string{"https://example.com/callback"},
			},
			expectedStatus: 400,
			expectedError:  "invalid_client_metadata",
		},
		{
			name: "Missing redirect URIs",
			requestBody: ClientRegistrationRequest{
				ClientID:   "test-client-3",
				ClientName: "Test Client",
			},
			expectedStatus: 400,
			expectedError:  "invalid_client_metadata",
		},
		{
			name: "Invalid redirect URI scheme",
			requestBody: ClientRegistrationRequest{
				ClientID:     "test-client-4",
				ClientName:   "Test Client",
				RedirectUris: []string{"ftp://example.com/callback"},
			},
			expectedStatus: 400,
			expectedError:  "invalid_redirect_uri",
		},
		{
			name: "HTTP redirect URI for non-localhost",
			requestBody: ClientRegistrationRequest{
				ClientID:     "test-client-5",
				ClientName:   "Test Client",
				RedirectUris: []string{"http://example.com/callback"},
			},
			expectedStatus: 400,
			expectedError:  "invalid_redirect_uri",
		},
		{
			name: "Valid HTTP redirect URI for localhost",
			requestBody: ClientRegistrationRequest{
				ClientID:     "test-client-6",
				ClientName:   "Test Client",
				RedirectUris: []string{"http://localhost:3000/callback"},
			},
			expectedStatus: 201,
		},
		{
			name: "Invalid scope",
			requestBody: ClientRegistrationRequest{
				ClientID:     "test-client-7",
				ClientName:   "Test Client",
				RedirectUris: []string{"https://example.com/callback"},
				Scope:        stringPtr("invalid_scope"),
			},
			expectedStatus: 400,
			expectedError:  "invalid_scope",
		},
		{
			name: "Public client",
			requestBody: ClientRegistrationRequest{
				ClientID:     "test-client-8",
				ClientName:   "Public Client",
				RedirectUris: []string{"https://example.com/callback"},
				ClientType:   stringPtr("public"),
			},
			expectedStatus: 201,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal request body
			body, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			// Create request
			req := httptest.NewRequest("POST", "/clients", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Call handler
			response := handle.RegisterClient(w, req)

			// Render the response to the writer
			if response != nil {
				if response.body != nil {
					response.Render(w, req)
				} else {
					w.WriteHeader(response.Code)
				}
			}

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check error response if expected
			if tt.expectedError != "" {
				var errorResp ErrorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &errorResp); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errorResp.Error != tt.expectedError {
					t.Errorf("Expected error %s, got %s", tt.expectedError, errorResp.Error)
				}
			}

			// Check success response
			if tt.expectedStatus == 201 {
				var clientResp ClientRegistrationResponse
				if err := json.Unmarshal(w.Body.Bytes(), &clientResp); err != nil {
					t.Fatalf("Failed to unmarshal client response: %v", err)
				}
				if clientResp.ClientID == "" {
					t.Error("Expected client_id to be set")
				}
				if clientResp.ClientSecret == nil || *clientResp.ClientSecret == "" {
					t.Error("Expected client_secret to be set")
				}
			}
		})
	}
}

func TestListClients(t *testing.T) {
	// Create a mock client service with some test clients
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	handle := NewHandle(clientService)

	// Add some test clients
	ctx := context.Background()
	client1 := &oauth2client.OAuth2Client{
		ClientID:      "client1",
		ClientSecret:  "secret1",
		ClientName:    "Test Client 1",
		RedirectURIs:  []string{"https://example.com/callback1"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		ClientType:    "confidential",
	}
	client2 := &oauth2client.OAuth2Client{
		ClientID:      "client2",
		ClientSecret:  "secret2",
		ClientName:    "Test Client 2",
		RedirectURIs:  []string{"https://example.com/callback2"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "email"},
		ClientType:    "public",
	}

	clientService.CreateClient(ctx, client1)
	clientService.CreateClient(ctx, client2)

	tests := []struct {
		name          string
		params        ListClientsParams
		expectedCount int
		expectedTotal int
	}{
		{
			name:          "List all clients",
			params:        ListClientsParams{},
			expectedCount: 2,
			expectedTotal: 2,
		},
		{
			name: "List with limit",
			params: ListClientsParams{
				Limit: intPtr(1),
			},
			expectedCount: 1,
			expectedTotal: 2,
		},
		{
			name: "List with offset",
			params: ListClientsParams{
				Offset: intPtr(1),
			},
			expectedCount: 1,
			expectedTotal: 2,
		},
		{
			name: "Filter by client type",
			params: ListClientsParams{
				ClientType: stringPtr("confidential"),
			},
			expectedCount: 1,
			expectedTotal: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/clients", nil)
			w := httptest.NewRecorder()

			response := handle.ListClients(w, req, tt.params)

			// Render the response to the writer
			if response != nil {
				if response.body != nil {
					response.Render(w, req)
				} else {
					w.WriteHeader(response.Code)
				}
			}

			if w.Code != 200 {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			var listResp ClientListResponse
			if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
				t.Fatalf("Failed to unmarshal list response: %v", err)
			}

			if len(listResp.Clients) != tt.expectedCount {
				t.Errorf("Expected %d clients, got %d", tt.expectedCount, len(listResp.Clients))
			}

			if listResp.Total != tt.expectedTotal {
				t.Errorf("Expected total %d, got %d", tt.expectedTotal, listResp.Total)
			}
		})
	}
}

func TestGetClient(t *testing.T) {
	// Create a mock client service with a test client
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	handle := NewHandle(clientService)

	// Add a test client
	ctx := context.Background()
	testClient := &oauth2client.OAuth2Client{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		ClientType:    "confidential",
	}
	clientService.CreateClient(ctx, testClient)

	tests := []struct {
		name           string
		clientID       string
		expectedStatus int
	}{
		{
			name:           "Get existing client",
			clientID:       "test-client",
			expectedStatus: 200,
		},
		{
			name:           "Get non-existing client",
			clientID:       "non-existing",
			expectedStatus: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/clients/"+tt.clientID, nil)
			w := httptest.NewRecorder()

			response := handle.GetClient(w, req, tt.clientID)

			// Render the response to the writer
			if response != nil {
				if response.body != nil {
					response.Render(w, req)
				} else {
					w.WriteHeader(response.Code)
				}
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == 200 {
				var clientResp ClientResponse
				if err := json.Unmarshal(w.Body.Bytes(), &clientResp); err != nil {
					t.Fatalf("Failed to unmarshal client response: %v", err)
				}
				if clientResp.ClientID != tt.clientID {
					t.Errorf("Expected client_id %s, got %s", tt.clientID, clientResp.ClientID)
				}
			}
		})
	}
}

func TestUpdateClient(t *testing.T) {
	// Create a mock client service with a test client
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	handle := NewHandle(clientService)

	// Add a test client
	ctx := context.Background()
	testClient := &oauth2client.OAuth2Client{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		ClientType:    "confidential",
	}
	clientService.CreateClient(ctx, testClient)

	tests := []struct {
		name           string
		clientID       string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:     "Valid client update",
			clientID: "test-client",
			requestBody: ClientUpdateRequest{
				ClientName:   stringPtr("Updated Client Name"),
				RedirectUris: []string{"https://example.com/new-callback"},
			},
			expectedStatus: 200,
		},
		{
			name:     "Update non-existing client",
			clientID: "non-existing",
			requestBody: ClientUpdateRequest{
				ClientName: stringPtr("Updated Name"),
			},
			expectedStatus: 404,
		},
		{
			name:     "Invalid redirect URI in update",
			clientID: "test-client",
			requestBody: ClientUpdateRequest{
				RedirectUris: []string{"ftp://example.com/callback"},
			},
			expectedStatus: 400,
			expectedError:  "invalid_redirect_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal request body
			body, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req := httptest.NewRequest("PUT", "/clients/"+tt.clientID, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			response := handle.UpdateClient(w, req, tt.clientID)

			// Render the response to the writer
			if response != nil {
				if response.body != nil {
					response.Render(w, req)
				} else {
					w.WriteHeader(response.Code)
				}
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedError != "" {
				var errorResp ErrorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &errorResp); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errorResp.Error != tt.expectedError {
					t.Errorf("Expected error %s, got %s", tt.expectedError, errorResp.Error)
				}
			}
		})
	}
}

func TestDeleteClient(t *testing.T) {
	// Create a mock client service with a test client
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	handle := NewHandle(clientService)

	// Add a test client
	ctx := context.Background()
	testClient := &oauth2client.OAuth2Client{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		ClientType:    "confidential",
	}
	clientService.CreateClient(ctx, testClient)

	tests := []struct {
		name           string
		clientID       string
		expectedStatus int
	}{
		{
			name:           "Delete existing client",
			clientID:       "test-client",
			expectedStatus: 204,
		},
		{
			name:           "Delete non-existing client",
			clientID:       "non-existing",
			expectedStatus: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/clients/"+tt.clientID, nil)
			w := httptest.NewRecorder()

			response := handle.DeleteClient(w, req, tt.clientID)

			// Render the response to the writer
			if response != nil {
				if response.body != nil {
					response.Render(w, req)
				} else {
					w.WriteHeader(response.Code)
				}
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestRegenerateClientSecret(t *testing.T) {
	// Create a mock client service with a test client
	clientService := oauth2client.NewClientService(oauth2client.NewInMemoryOAuth2ClientRepository())
	handle := NewHandle(clientService)

	// Add a test client
	ctx := context.Background()
	testClient := &oauth2client.OAuth2Client{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		ClientType:    "confidential",
	}
	clientService.CreateClient(ctx, testClient)

	tests := []struct {
		name           string
		clientID       string
		expectedStatus int
	}{
		{
			name:           "Regenerate secret for existing client",
			clientID:       "test-client",
			expectedStatus: 200,
		},
		{
			name:           "Regenerate secret for non-existing client",
			clientID:       "non-existing",
			expectedStatus: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/clients/"+tt.clientID+"/regenerate-secret", nil)
			w := httptest.NewRecorder()

			response := handle.RegenerateClientSecret(w, req, tt.clientID)

			// Render the response to the writer
			if response != nil {
				if response.body != nil {
					response.Render(w, req)
				} else {
					w.WriteHeader(response.Code)
				}
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == 200 {
				var secretResp ClientSecretResponse
				if err := json.Unmarshal(w.Body.Bytes(), &secretResp); err != nil {
					t.Fatalf("Failed to unmarshal secret response: %v", err)
				}
				if secretResp.ClientID != tt.clientID {
					t.Errorf("Expected client_id %s, got %s", tt.clientID, secretResp.ClientID)
				}
				if secretResp.ClientSecret == "" {
					t.Error("Expected new client_secret to be set")
				}
				if secretResp.ClientSecret == "test-secret" {
					t.Error("Expected new client_secret to be different from old one")
				}
				if secretResp.UpdatedAt.IsZero() {
					t.Error("Expected updated_at to be set")
				}
				// Check that updated_at is recent (within last minute)
				if time.Since(secretResp.UpdatedAt) > time.Minute {
					t.Error("Expected updated_at to be recent")
				}
			}
		})
	}
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
