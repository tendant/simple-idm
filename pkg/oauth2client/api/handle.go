package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/tendant/simple-idm/pkg/oauth2client"
)

// Handle implements the ServerInterface for OAuth2 client registration
type Handle struct {
	clientService *oauth2client.ClientService
}

// NewHandle creates a new OAuth2 client registration API handler
func NewHandle(clientService *oauth2client.ClientService) *Handle {
	return &Handle{
		clientService: clientService,
	}
}

// ListClients implements ServerInterface.ListClients
func (h *Handle) ListClients(w http.ResponseWriter, r *http.Request, params ListClientsParams) *Response {
	// Set default values
	limit := 20
	offset := 0

	if params.Limit != nil {
		limit = *params.Limit
	}
	if params.Offset != nil {
		offset = *params.Offset
	}

	// Get all clients from service
	clients := h.clientService.ListClients()

	// Convert map to slice for filtering and pagination
	var clientList []*oauth2client.OAuth2Client
	for _, client := range clients {
		clientList = append(clientList, client)
	}

	total := len(clientList)

	// Apply pagination
	start := offset
	end := offset + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedClients := clientList[start:end]

	// Convert to response format
	var responseClients []ClientResponse
	for _, client := range paginatedClients {
		responseClients = append(responseClients, h.convertToClientResponse(client))
	}

	response := ClientListResponse{
		Clients: responseClients,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}

	return ListClientsJSON200Response(response)
}

// RegisterClient implements ServerInterface.RegisterClient
func (h *Handle) RegisterClient(w http.ResponseWriter, r *http.Request) *Response {
	ctx := r.Context()

	// Parse request body
	var req ClientRegistrationRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		slog.Error("Failed to parse registration request", "error", err)
		return RegisterClientJSON400Response(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
	}

	// Validate request according to RFC 7591
	if validationErrors := ValidateClientRegistrationRequest(&req); len(validationErrors) > 0 {
		// Return the first validation error (could be enhanced to return all errors)
		firstError := validationErrors[0]
		slog.Error("Client registration validation failed", "errors", validationErrors)
		return RegisterClientJSON400Response(ErrorResponse{
			Error:            firstError.Code,
			ErrorDescription: firstError.Message,
		})
	}

	clientSecret, err := h.clientService.GenerateClientSecret()
	if err != nil {
		slog.Error("Failed to generate client secret", "error", err)
		return RegisterClientJSON400Response(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to generate client credentials",
		})
	}

	// Set defaults
	clientType := "confidential"
	if req.ClientType != nil {
		clientType = *req.ClientType
	}

	responseTypes := []string{"code"}
	if len(req.ResponseTypes) > 0 {
		responseTypes = make([]string, len(req.ResponseTypes))
		copy(responseTypes, req.ResponseTypes)
	}

	grantTypes := []string{"authorization_code"}
	if len(req.GrantTypes) > 0 {
		grantTypes = make([]string, len(req.GrantTypes))
		copy(grantTypes, req.GrantTypes)
	}

	// Create OAuth2 client
	client := &oauth2client.OAuth2Client{
		ClientID:      req.ClientID,
		ClientSecret:  clientSecret,
		ClientName:    req.ClientName,
		RedirectURIs:  req.RedirectUris,
		ResponseTypes: responseTypes,
		GrantTypes:    grantTypes,
		Scopes:        h.parseScopes(req.Scope),
		ClientType:    clientType,
		RequirePKCE:   clientType == "public", // Public clients require PKCE
	}

	// Create client through service
	createdClient, err := h.clientService.CreateClient(ctx, client)
	if err != nil {
		slog.Error("Failed to create client", "error", err, "client_id", req.ClientID)
		return RegisterClientJSON400Response(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to create client",
		})
	}

	// Build response using the created client entity
	now := time.Now()
	response := ClientRegistrationResponse{
		ClientID:      createdClient.ClientID,
		ClientSecret:  &createdClient.ClientSecret,
		ClientName:    createdClient.ClientName,
		ClientType:    createdClient.ClientType,
		RedirectUris:  createdClient.RedirectURIs,
		ResponseTypes: createdClient.ResponseTypes,
		GrantTypes:    createdClient.GrantTypes,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Convert scopes to space-separated string
	if len(createdClient.Scopes) > 0 {
		scopeStr := strings.Join(createdClient.Scopes, " ")
		response.Scope = &scopeStr
	}

	slog.Info("OAuth2 client registered successfully", "client_id", req.ClientID, "client_name", req.ClientName)

	return RegisterClientJSON201Response(response)
}

// GetClient implements ServerInterface.GetClient
func (h *Handle) GetClient(w http.ResponseWriter, r *http.Request, clientID string) *Response {
	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		slog.Error("Failed to get client", "error", err, "client_id", clientID)
		return GetClientJSON404Response(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
	}

	response := h.convertToClientResponse(client)
	return GetClientJSON200Response(response)
}

// UpdateClient implements ServerInterface.UpdateClient
func (h *Handle) UpdateClient(w http.ResponseWriter, r *http.Request, clientID string) *Response {
	ctx := r.Context()

	// Check if client exists
	existingClient, err := h.clientService.GetClient(clientID)
	if err != nil {
		slog.Error("Client not found for update", "error", err, "client_id", clientID)
		return UpdateClientJSON404Response(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
	}

	// Parse request body
	var req ClientUpdateRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		slog.Error("Failed to parse update request", "error", err)
		return UpdateClientJSON400Response(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body",
		})
	}

	// Validate request according to RFC 7591
	if validationErrors := ValidateClientUpdateRequest(&req); len(validationErrors) > 0 {
		// Return the first validation error (could be enhanced to return all errors)
		firstError := validationErrors[0]
		slog.Error("Client update validation failed", "errors", validationErrors)
		return UpdateClientJSON400Response(ErrorResponse{
			Error:            firstError.Code,
			ErrorDescription: firstError.Message,
		})
	}

	// Update client fields
	updatedClient := *existingClient // Copy existing client

	if req.ClientName != nil {
		updatedClient.ClientName = *req.ClientName
	}
	if len(req.RedirectUris) > 0 {
		updatedClient.RedirectURIs = req.RedirectUris
	}
	if req.ClientType != nil {
		updatedClient.ClientType = *req.ClientType
	}
	if len(req.ResponseTypes) > 0 {
		responseTypes := make([]string, len(req.ResponseTypes))
		copy(responseTypes, req.ResponseTypes)
		updatedClient.ResponseTypes = responseTypes
	}
	if len(req.GrantTypes) > 0 {
		grantTypes := make([]string, len(req.GrantTypes))
		copy(grantTypes, req.GrantTypes)
		updatedClient.GrantTypes = grantTypes
	}
	if req.Scope != nil {
		updatedClient.Scopes = h.parseScopes(req.Scope)
	}

	// Update client through service
	finalClient, err := h.clientService.UpdateClient(ctx, &updatedClient)
	if err != nil {
		slog.Error("Failed to update client", "error", err, "client_id", clientID)
		return UpdateClientJSON400Response(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to update client",
		})
	}

	response := h.convertToClientResponse(finalClient)
	slog.Info("OAuth2 client updated successfully", "client_id", clientID)

	return UpdateClientJSON200Response(response)
}

// DeleteClient implements ServerInterface.DeleteClient
func (h *Handle) DeleteClient(w http.ResponseWriter, r *http.Request, clientID string) *Response {
	ctx := r.Context()

	// Check if client exists
	_, err := h.clientService.GetClient(clientID)
	if err != nil {
		slog.Error("Client not found for deletion", "error", err, "client_id", clientID)
		return DeleteClientJSON404Response(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
	}

	// Delete client through service
	err = h.clientService.DeleteClient(ctx, clientID)
	if err != nil {
		slog.Error("Failed to delete client", "error", err, "client_id", clientID)
		return DeleteClientJSON401Response(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to delete client",
		})
	}

	slog.Info("OAuth2 client deleted successfully", "client_id", clientID)

	// Return 204 No Content
	return &Response{Code: 204}
}

// RegenerateClientSecret implements ServerInterface.RegenerateClientSecret
func (h *Handle) RegenerateClientSecret(w http.ResponseWriter, r *http.Request, clientID string) *Response {
	ctx := r.Context()

	// Check if client exists
	existingClient, err := h.clientService.GetClient(clientID)
	if err != nil {
		slog.Error("Client not found for secret regeneration", "error", err, "client_id", clientID)
		return RegenerateClientSecretJSON404Response(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client not found",
		})
	}

	// Generate new client secret
	newSecret, err := h.clientService.GenerateClientSecret()
	if err != nil {
		slog.Error("Failed to generate new client secret", "error", err)
		return RegenerateClientSecretJSON401Response(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to generate new client secret",
		})
	}

	// Update client with new secret
	updatedClient := *existingClient
	updatedClient.ClientSecret = newSecret

	_, err = h.clientService.UpdateClient(ctx, &updatedClient)
	if err != nil {
		slog.Error("Failed to update client with new secret", "error", err, "client_id", clientID)
		return RegenerateClientSecretJSON401Response(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to update client secret",
		})
	}

	response := ClientSecretResponse{
		ClientID:     clientID,
		ClientSecret: newSecret,
		UpdatedAt:    time.Now(),
	}

	slog.Info("OAuth2 client secret regenerated successfully", "client_id", clientID)

	return RegenerateClientSecretJSON200Response(response)
}

// Helper methods
func (h *Handle) parseScopes(scope *string) []string {
	if scope == nil || *scope == "" {
		return []string{"openid", "profile", "email"}
	}
	return strings.Fields(*scope)
}

func (h *Handle) convertToClientResponse(client *oauth2client.OAuth2Client) ClientResponse {

	response := ClientResponse{
		ClientID:      client.ClientID,
		ClientName:    client.ClientName,
		ClientType:    client.ClientType,
		RedirectUris:  client.RedirectURIs,
		ResponseTypes: client.ResponseTypes,
		GrantTypes:    client.GrantTypes,
		CreatedAt:     client.CreatedAt,
		UpdatedAt:     client.UpdatedAt,
	}

	// Convert scopes to space-separated string
	if len(client.Scopes) > 0 {
		scopeStr := strings.Join(client.Scopes, " ")
		response.Scope = &scopeStr
	}

	return response
}

// NewHandler creates the HTTP handler for OAuth2 client registration API
func NewHandler(handle *Handle) http.Handler {
	return Handler(handle)
}
