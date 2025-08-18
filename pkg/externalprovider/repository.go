package externalprovider

import (
	"fmt"
	"sync"
	"time"
)

// ExternalProviderRepository defines the interface for managing external providers
type ExternalProviderRepository interface {
	// Provider management
	GetProvider(providerID string) (*ExternalProvider, error)
	GetAllProviders() (map[string]*ExternalProvider, error)
	GetEnabledProviders() (map[string]*ExternalProvider, error)
	CreateProvider(provider *ExternalProvider) error
	UpdateProvider(provider *ExternalProvider) error
	DeleteProvider(providerID string) error
	EnableProvider(providerID string) error
	DisableProvider(providerID string) error

	// OAuth2 state management
	StoreState(state *OAuth2State) error
	GetState(stateValue string) (*OAuth2State, error)
	DeleteState(stateValue string) error
	CleanupExpiredStates() error
}

// InMemoryExternalProviderRepository implements ExternalProviderRepository using in-memory storage
type InMemoryExternalProviderRepository struct {
	providers map[string]*ExternalProvider
	states    map[string]*OAuth2State
	mutex     sync.RWMutex
}

// NewInMemoryExternalProviderRepository creates a new in-memory repository with default providers
func NewInMemoryExternalProviderRepository() *InMemoryExternalProviderRepository {
	repo := &InMemoryExternalProviderRepository{
		providers: make(map[string]*ExternalProvider),
		states:    make(map[string]*OAuth2State),
	}

	return repo
}

// GetProvider retrieves a provider by ID
func (r *InMemoryExternalProviderRepository) GetProvider(providerID string) (*ExternalProvider, error) {
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
func (r *InMemoryExternalProviderRepository) GetAllProviders() (map[string]*ExternalProvider, error) {
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
func (r *InMemoryExternalProviderRepository) GetEnabledProviders() (map[string]*ExternalProvider, error) {
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
func (r *InMemoryExternalProviderRepository) CreateProvider(provider *ExternalProvider) error {
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

	return nil
}

// UpdateProvider updates an existing provider
func (r *InMemoryExternalProviderRepository) UpdateProvider(provider *ExternalProvider) error {
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

	return nil
}

// DeleteProvider deletes a provider
func (r *InMemoryExternalProviderRepository) DeleteProvider(providerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[providerID]; !exists {
		return fmt.Errorf("provider not found: %s", providerID)
	}

	delete(r.providers, providerID)
	return nil
}

// EnableProvider enables a provider
func (r *InMemoryExternalProviderRepository) EnableProvider(providerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	provider, exists := r.providers[providerID]
	if !exists {
		return fmt.Errorf("provider not found: %s", providerID)
	}

	provider.Enabled = true
	return nil
}

// DisableProvider disables a provider
func (r *InMemoryExternalProviderRepository) DisableProvider(providerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	provider, exists := r.providers[providerID]
	if !exists {
		return fmt.Errorf("provider not found: %s", providerID)
	}

	provider.Enabled = false
	return nil
}

// StoreState stores an OAuth2 state for security validation
func (r *InMemoryExternalProviderRepository) StoreState(state *OAuth2State) error {
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

	return nil
}

// GetState retrieves an OAuth2 state by state value
func (r *InMemoryExternalProviderRepository) GetState(stateValue string) (*OAuth2State, error) {
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

// DeleteState deletes an OAuth2 state
func (r *InMemoryExternalProviderRepository) DeleteState(stateValue string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.states[stateValue]; !exists {
		return fmt.Errorf("state not found: %s", stateValue)
	}

	delete(r.states, stateValue)
	return nil
}

// CleanupExpiredStates removes expired OAuth2 states
func (r *InMemoryExternalProviderRepository) CleanupExpiredStates() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now().Unix()
	for stateValue, state := range r.states {
		if now > state.ExpiresAt {
			delete(r.states, stateValue)
		}
	}

	return nil
}

// GetStateCount returns the number of stored states (useful for testing/monitoring)
func (r *InMemoryExternalProviderRepository) GetStateCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return len(r.states)
}

// GetProviderCount returns the number of stored providers (useful for testing/monitoring)
func (r *InMemoryExternalProviderRepository) GetProviderCount() int {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return len(r.providers)
}
