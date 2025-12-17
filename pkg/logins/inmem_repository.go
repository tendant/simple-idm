package logins

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Common errors
var (
	ErrLoginNotFound = errors.New("login not found")
)

// InMemoryLoginsRepository implements LoginsRepository using in-memory storage
type InMemoryLoginsRepository struct {
	mu     sync.RWMutex
	logins map[uuid.UUID]LoginEntity
}

// NewInMemoryLoginsRepository creates a new in-memory logins repository
func NewInMemoryLoginsRepository() *InMemoryLoginsRepository {
	return &InMemoryLoginsRepository{
		logins: make(map[uuid.UUID]LoginEntity),
	}
}

// GetLogin retrieves a login by ID
func (r *InMemoryLoginsRepository) GetLogin(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[id]
	if !ok || login.DeletedAtValid {
		return LoginEntity{}, ErrLoginNotFound
	}
	return login, nil
}

// GetLoginByUsername retrieves a login by username
func (r *InMemoryLoginsRepository) GetLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, login := range r.logins {
		if login.DeletedAtValid {
			continue
		}
		if login.UsernameValid == usernameValid && login.Username == username {
			return login, nil
		}
	}
	return LoginEntity{}, ErrLoginNotFound
}

// ListLogins retrieves a list of logins with pagination
func (r *InMemoryLoginsRepository) ListLogins(ctx context.Context, params ListLoginsParams) ([]LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect all non-deleted logins
	var allLogins []LoginEntity
	for _, login := range r.logins {
		if !login.DeletedAtValid {
			allLogins = append(allLogins, login)
		}
	}

	// Apply pagination
	start := int(params.Offset)
	if start >= len(allLogins) {
		return []LoginEntity{}, nil
	}

	end := start + int(params.Limit)
	if end > len(allLogins) {
		end = len(allLogins)
	}

	return allLogins[start:end], nil
}

// CountLogins returns the total number of logins
func (r *InMemoryLoginsRepository) CountLogins(ctx context.Context) (int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var count int64
	for _, login := range r.logins {
		if !login.DeletedAtValid {
			count++
		}
	}
	return count, nil
}

// SearchLogins searches for logins by username pattern
func (r *InMemoryLoginsRepository) SearchLogins(ctx context.Context, params SearchLoginsParams) ([]LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []LoginEntity
	query := strings.ToLower(params.Query)

	for _, login := range r.logins {
		if login.DeletedAtValid {
			continue
		}
		if strings.Contains(strings.ToLower(login.Username), query) {
			matches = append(matches, login)
		}
	}

	// Apply pagination
	start := int(params.Offset)
	if start >= len(matches) {
		return []LoginEntity{}, nil
	}

	end := start + int(params.Limit)
	if end > len(matches) {
		end = len(matches)
	}

	return matches[start:end], nil
}

// CreateLogin creates a new login
func (r *InMemoryLoginsRepository) CreateLogin(ctx context.Context, params CreateLoginParams) (LoginEntity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	login := LoginEntity{
		ID:             uuid.New(),
		Username:       params.Username,
		UsernameValid:  params.UsernameValid,
		Password:       params.Password,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      params.CreatedBy,
		CreatedByValid: params.CreatedByValid,
	}

	r.logins[login.ID] = login
	return login, nil
}

// UpdateLogin updates a login's username
func (r *InMemoryLoginsRepository) UpdateLogin(ctx context.Context, params UpdateLoginParams) (LoginEntity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[params.ID]
	if !ok || login.DeletedAtValid {
		return LoginEntity{}, ErrLoginNotFound
	}

	login.Username = params.Username
	login.UsernameValid = params.UsernameValid
	login.UpdatedAt = time.Now()

	r.logins[params.ID] = login
	return login, nil
}

// DeleteLogin soft deletes a login
func (r *InMemoryLoginsRepository) DeleteLogin(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[id]
	if !ok {
		return nil // Idempotent delete
	}

	login.DeletedAt = time.Now()
	login.DeletedAtValid = true
	r.logins[id] = login
	return nil
}

// WithTx returns the same repository (no-op for in-memory)
func (r *InMemoryLoginsRepository) WithTx(tx interface{}) LoginsRepository {
	return r
}

// SeedLogin adds a login directly (for testing/initialization)
func (r *InMemoryLoginsRepository) SeedLogin(login LoginEntity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logins[login.ID] = login
}
