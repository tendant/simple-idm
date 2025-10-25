package externalprovider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileExternalProviderRepository implements ExternalProviderRepository using file-based storage
type FileExternalProviderRepository struct {
	dataDir   string
	providers map[string]*ExternalProvider
	states    map[string]*OAuth2State
	mutex     sync.RWMutex
}

// externalProviderData represents the structure of data stored in the JSON file
type externalProviderData struct {
	Providers []*ExternalProvider `json:"providers"`
	States    []*OAuth2State      `json:"states"`
}

// NewFileExternalProviderRepository creates a new file-based external provider repository
func NewFileExternalProviderRepository(dataDir string) (*FileExternalProviderRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileExternalProviderRepository{
		dataDir:   dataDir,
		providers: make(map[string]*ExternalProvider),
		states:    make(map[string]*OAuth2State),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// GetProvider retrieves a provider by ID
func (r *FileExternalProviderRepository) GetProvider(providerID string) (*ExternalProvider, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	provider, exists := r.providers[providerID]
	if !exists {
		return nil, fmt.Errorf("provider not found: %s", providerID)
	}

	// Return a copy to prevent external modifications
	providerCopy := *provider
	return &providerCopy, nil
}

// GetAllProviders returns all providers
func (r *FileExternalProviderRepository) GetAllProviders() (map[string]*ExternalProvider, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]*ExternalProvider)
	for id, provider := range r.providers {
		// Return copies to prevent external modifications
		providerCopy := *provider
		result[id] = &providerCopy
	}

	return result, nil
}

// GetEnabledProviders returns only enabled providers
func (r *FileExternalProviderRepository) GetEnabledProviders() (map[string]*ExternalProvider, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]*ExternalProvider)
	for id, provider := range r.providers {
		if provider.Enabled {
			// Return copies to prevent external modifications
			providerCopy := *provider
			result[id] = &providerCopy
		}
	}

	return result, nil
}

// CreateProvider creates a new provider
func (r *FileExternalProviderRepository) CreateProvider(provider *ExternalProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	if err := provider.ValidateConfig(); err != nil {
		return fmt.Errorf("invalid provider configuration: %w", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[provider.ID]; exists {
		return fmt.Errorf("provider already exists: %s", provider.ID)
	}

	// Store a copy to prevent external modifications
	providerCopy := *provider
	r.providers[provider.ID] = &providerCopy

	// Persist to file
	return r.save()
}

// UpdateProvider updates an existing provider
func (r *FileExternalProviderRepository) UpdateProvider(provider *ExternalProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	if err := provider.ValidateConfig(); err != nil {
		return fmt.Errorf("invalid provider configuration: %w", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[provider.ID]; !exists {
		return fmt.Errorf("provider not found: %s", provider.ID)
	}

	// Store a copy to prevent external modifications
	providerCopy := *provider
	r.providers[provider.ID] = &providerCopy

	// Persist to file
	return r.save()
}

// DeleteProvider deletes a provider by ID
func (r *FileExternalProviderRepository) DeleteProvider(providerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[providerID]; !exists {
		return fmt.Errorf("provider not found: %s", providerID)
	}

	delete(r.providers, providerID)

	// Persist to file
	return r.save()
}

// EnableProvider enables a provider
func (r *FileExternalProviderRepository) EnableProvider(providerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	provider, exists := r.providers[providerID]
	if !exists {
		return fmt.Errorf("provider not found: %s", providerID)
	}

	provider.Enabled = true

	// Persist to file
	return r.save()
}

// DisableProvider disables a provider
func (r *FileExternalProviderRepository) DisableProvider(providerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	provider, exists := r.providers[providerID]
	if !exists {
		return fmt.Errorf("provider not found: %s", providerID)
	}

	provider.Enabled = false

	// Persist to file
	return r.save()
}

// StoreState stores an OAuth2 state
func (r *FileExternalProviderRepository) StoreState(state *OAuth2State) error {
	if state == nil {
		return fmt.Errorf("state cannot be nil")
	}

	if state.State == "" {
		return fmt.Errorf("state value cannot be empty")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Store a copy to prevent external modifications
	stateCopy := *state
	r.states[state.State] = &stateCopy

	// Persist to file
	return r.save()
}

// GetState retrieves an OAuth2 state by value
func (r *FileExternalProviderRepository) GetState(stateValue string) (*OAuth2State, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	state, exists := r.states[stateValue]
	if !exists {
		return nil, fmt.Errorf("state not found: %s", stateValue)
	}

	// Check if state is expired
	if time.Now().Unix() > state.ExpiresAt {
		return nil, fmt.Errorf("state expired: %s", stateValue)
	}

	// Return a copy to prevent external modifications
	stateCopy := *state
	return &stateCopy, nil
}

// DeleteState deletes an OAuth2 state by value
func (r *FileExternalProviderRepository) DeleteState(stateValue string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.states[stateValue]; !exists {
		return fmt.Errorf("state not found: %s", stateValue)
	}

	delete(r.states, stateValue)

	// Persist to file
	return r.save()
}

// CleanupExpiredStates removes all expired states
func (r *FileExternalProviderRepository) CleanupExpiredStates() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now().Unix()
	for stateValue, state := range r.states {
		if now > state.ExpiresAt {
			delete(r.states, stateValue)
		}
	}

	// Persist to file
	return r.save()
}

// GetStateCount returns the number of stored states (for monitoring)
func (r *FileExternalProviderRepository) GetStateCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.states)
}

// GetProviderCount returns the number of registered providers (for monitoring)
func (r *FileExternalProviderRepository) GetProviderCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.providers)
}

// load reads external provider data from file
func (r *FileExternalProviderRepository) load() error {
	filePath := filepath.Join(r.dataDir, "external_providers.json")

	// If file doesn't exist, start with empty maps
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty maps
	if len(data) == 0 {
		return nil
	}

	var epData externalProviderData
	if err := json.Unmarshal(data, &epData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to maps
	r.providers = make(map[string]*ExternalProvider)
	for _, provider := range epData.Providers {
		r.providers[provider.ID] = provider
	}

	r.states = make(map[string]*OAuth2State)
	for _, state := range epData.States {
		r.states[state.State] = state
	}

	return nil
}

// save writes external provider data to file atomically
func (r *FileExternalProviderRepository) save() error {
	// Convert maps to slices
	providers := make([]*ExternalProvider, 0, len(r.providers))
	for _, provider := range r.providers {
		providers = append(providers, provider)
	}

	states := make([]*OAuth2State, 0, len(r.states))
	for _, state := range r.states {
		states = append(states, state)
	}

	data := externalProviderData{
		Providers: providers,
		States:    states,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "external_providers.json.tmp")
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "external_providers.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
