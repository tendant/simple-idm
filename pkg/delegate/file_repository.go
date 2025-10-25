package delegate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/mapper"
)

// DelegationRecord represents a delegation relationship
type DelegationRecord struct {
	DelegatorID uuid.UUID `json:"delegator_id"` // The user who is delegating
	DelegateeID uuid.UUID `json:"delegatee_id"` // The user receiving delegation
}

// FileDelegationRepository implements DelegationRepository using file-based storage
type FileDelegationRepository struct {
	dataDir     string
	delegations []DelegationRecord
	userMapper  mapper.UserMapper
	mutex       sync.RWMutex
}

// delegationData represents the structure of data stored in the JSON file
type delegationData struct {
	Delegations []DelegationRecord `json:"delegations"`
}

// NewFileDelegationRepository creates a new file-based delegation repository
func NewFileDelegationRepository(dataDir string, userMapper mapper.UserMapper) (*FileDelegationRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileDelegationRepository{
		dataDir:     dataDir,
		delegations: []DelegationRecord{},
		userMapper:  userMapper,
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// FindDelegators retrieves all delegator users for the specified delegatee
func (r *FileDelegationRepository) FindDelegators(ctx context.Context, delegateeUuid uuid.UUID) ([]mapper.User, error) {
	r.mutex.RLock()
	delegatorIDs := make([]uuid.UUID, 0)
	for _, delegation := range r.delegations {
		if delegation.DelegateeID == delegateeUuid {
			delegatorIDs = append(delegatorIDs, delegation.DelegatorID)
		}
	}
	r.mutex.RUnlock()

	// Retrieve full user objects for each delegator
	users := make([]mapper.User, 0, len(delegatorIDs))
	for _, delegatorID := range delegatorIDs {
		user, err := r.userMapper.GetUserByUserID(ctx, delegatorID)
		if err != nil {
			// Skip users that can't be found
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// AddDelegation adds a new delegation relationship
func (r *FileDelegationRepository) AddDelegation(ctx context.Context, delegatorID, delegateeID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if delegation already exists
	for _, delegation := range r.delegations {
		if delegation.DelegatorID == delegatorID && delegation.DelegateeID == delegateeID {
			return fmt.Errorf("delegation already exists")
		}
	}

	delegation := DelegationRecord{
		DelegatorID: delegatorID,
		DelegateeID: delegateeID,
	}

	r.delegations = append(r.delegations, delegation)
	return r.save()
}

// RemoveDelegation removes a delegation relationship
func (r *FileDelegationRepository) RemoveDelegation(ctx context.Context, delegatorID, delegateeID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	newDelegations := make([]DelegationRecord, 0, len(r.delegations))
	found := false

	for _, delegation := range r.delegations {
		if delegation.DelegatorID == delegatorID && delegation.DelegateeID == delegateeID {
			found = true
			// Skip this delegation (remove it)
			continue
		}
		newDelegations = append(newDelegations, delegation)
	}

	if !found {
		return fmt.Errorf("delegation not found")
	}

	r.delegations = newDelegations
	return r.save()
}

// load reads delegation data from file
func (r *FileDelegationRepository) load() error {
	filePath := filepath.Join(r.dataDir, "delegations.json")

	// If file doesn't exist, start with empty list
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// If file is empty, start with empty list
	if len(data) == 0 {
		return nil
	}

	var delData delegationData
	if err := json.Unmarshal(data, &delData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	r.delegations = delData.Delegations
	if r.delegations == nil {
		r.delegations = []DelegationRecord{}
	}

	return nil
}

// save writes delegation data to file atomically
func (r *FileDelegationRepository) save() error {
	data := delegationData{
		Delegations: r.delegations,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "delegations.json.tmp")
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "delegations.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
