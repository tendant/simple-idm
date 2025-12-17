package login

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Common errors for in-memory repository
var (
	ErrLoginNotFound           = errors.New("login not found")
	ErrTokenNotFound           = errors.New("token not found")
	ErrTokenExpired            = errors.New("token expired")
	ErrTokenAlreadyUsed        = errors.New("token already used")
	ErrInvalidUsernamePassword = errors.New("invalid username or password")
)

// InMemoryLoginRepository implements LoginRepository using in-memory storage
type InMemoryLoginRepository struct {
	mu                  sync.RWMutex
	logins              map[uuid.UUID]LoginEntity
	loginsByUsername    map[string]uuid.UUID           // username -> loginID
	loginsByEmail       map[string][]uuid.UUID         // email -> []loginID
	passwordResetTokens map[string]passwordResetData   // token -> data
	magicLinkTokens     map[string]magicLinkData       // token -> data
	passwordHistory     map[uuid.UUID][]PasswordHistoryEntry
	loginAttempts       map[uuid.UUID][]LoginAttempt
}

type passwordResetData struct {
	ID       uuid.UUID
	LoginID  uuid.UUID
	Token    string
	ExpireAt time.Time
	UsedAt   *time.Time
}

type magicLinkData struct {
	ID        uuid.UUID
	LoginID   uuid.UUID
	Token     string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// NewInMemoryLoginRepository creates a new in-memory login repository
func NewInMemoryLoginRepository() *InMemoryLoginRepository {
	return &InMemoryLoginRepository{
		logins:              make(map[uuid.UUID]LoginEntity),
		loginsByUsername:    make(map[string]uuid.UUID),
		loginsByEmail:       make(map[string][]uuid.UUID),
		passwordResetTokens: make(map[string]passwordResetData),
		magicLinkTokens:     make(map[string]magicLinkData),
		passwordHistory:     make(map[uuid.UUID][]PasswordHistoryEntry),
		loginAttempts:       make(map[uuid.UUID][]LoginAttempt),
	}
}

// FindLoginByUsername finds a login by username
func (r *InMemoryLoginRepository) FindLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !usernameValid {
		return LoginEntity{}, ErrLoginNotFound
	}

	loginID, ok := r.loginsByUsername[username]
	if !ok {
		return LoginEntity{}, ErrLoginNotFound
	}

	login, ok := r.logins[loginID]
	if !ok {
		return LoginEntity{}, ErrLoginNotFound
	}
	return login, nil
}

// FindLoginsByEmail finds all logins associated with an email address
func (r *InMemoryLoginRepository) FindLoginsByEmail(ctx context.Context, email string) ([]LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	loginIDs, ok := r.loginsByEmail[email]
	if !ok {
		return []LoginEntity{}, nil
	}

	logins := make([]LoginEntity, 0, len(loginIDs))
	for _, id := range loginIDs {
		if login, ok := r.logins[id]; ok {
			logins = append(logins, login)
		}
	}
	return logins, nil
}

// FindPrimaryLoginByEmail finds the primary login associated with an email address
func (r *InMemoryLoginRepository) FindPrimaryLoginByEmail(ctx context.Context, email string) (LoginEntity, error) {
	logins, err := r.FindLoginsByEmail(ctx, email)
	if err != nil {
		return LoginEntity{}, err
	}
	if len(logins) == 0 {
		return LoginEntity{}, ErrLoginNotFound
	}
	return logins[0], nil // Return first login as primary
}

// GetLoginById returns a login by ID
func (r *InMemoryLoginRepository) GetLoginById(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[id]
	if !ok {
		return LoginEntity{}, ErrLoginNotFound
	}
	return login, nil
}

// GetPasswordVersion gets the password version for a login
func (r *InMemoryLoginRepository) GetPasswordVersion(ctx context.Context, id uuid.UUID) (int32, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[id]
	if !ok {
		return 0, false, ErrLoginNotFound
	}
	return login.PasswordVersion, true, nil
}

// ResetPassword resets a password by username
func (r *InMemoryLoginRepository) ResetPassword(ctx context.Context, arg PasswordParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	loginID, ok := r.loginsByUsername[arg.Username]
	if !ok {
		return ErrLoginNotFound
	}

	login := r.logins[loginID]
	login.Password = arg.Password
	login.UpdatedAt = time.Now()
	r.logins[loginID] = login
	return nil
}

// ResetPasswordById resets a password by login ID
func (r *InMemoryLoginRepository) ResetPasswordById(ctx context.Context, arg PasswordParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[arg.ID]
	if !ok {
		return ErrLoginNotFound
	}

	login.Password = arg.Password
	login.UpdatedAt = time.Now()
	r.logins[arg.ID] = login
	return nil
}

// UpdateUserPassword updates a user's password
func (r *InMemoryLoginRepository) UpdateUserPassword(ctx context.Context, arg PasswordParams) error {
	return r.ResetPasswordById(ctx, arg)
}

// UpdateUserPasswordAndVersion updates a user's password and version
func (r *InMemoryLoginRepository) UpdateUserPasswordAndVersion(ctx context.Context, arg PasswordParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[arg.ID]
	if !ok {
		return ErrLoginNotFound
	}

	login.Password = arg.Password
	login.PasswordVersion = arg.PasswordVersion
	login.UpdatedAt = time.Now()
	r.logins[arg.ID] = login
	return nil
}

// GetPasswordUpdatedAt gets the password updated at timestamp for a login
func (r *InMemoryLoginRepository) GetPasswordUpdatedAt(ctx context.Context, loginID uuid.UUID) (time.Time, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[loginID]
	if !ok {
		return time.Time{}, false, ErrLoginNotFound
	}
	return login.PasswordUpdatedAt, !login.PasswordUpdatedAt.IsZero(), nil
}

// GetPasswordExpiresAt gets the password expire at timestamp for a login
func (r *InMemoryLoginRepository) GetPasswordExpiresAt(ctx context.Context, loginID uuid.UUID) (time.Time, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[loginID]
	if !ok {
		return time.Time{}, false, ErrLoginNotFound
	}
	return login.PasswordExpiresAt, !login.PasswordExpiresAt.IsZero(), nil
}

// UpdatePasswordTimestamps updates the password updated at and expire at timestamps for a login
func (r *InMemoryLoginRepository) UpdatePasswordTimestamps(ctx context.Context, loginID uuid.UUID, updatedAt, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[loginID]
	if !ok {
		return ErrLoginNotFound
	}

	login.PasswordUpdatedAt = updatedAt
	login.PasswordExpiresAt = expiresAt
	r.logins[loginID] = login
	return nil
}

// InitPasswordResetToken initializes a password reset token
func (r *InMemoryLoginRepository) InitPasswordResetToken(ctx context.Context, arg PasswordResetTokenParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.passwordResetTokens[arg.Token] = passwordResetData{
		ID:       uuid.New(),
		LoginID:  arg.LoginID,
		Token:    arg.Token,
		ExpireAt: arg.ExpireAt,
	}
	return nil
}

// ValidatePasswordResetToken validates a password reset token
func (r *InMemoryLoginRepository) ValidatePasswordResetToken(ctx context.Context, token string) (PasswordResetToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	data, ok := r.passwordResetTokens[token]
	if !ok {
		return PasswordResetToken{}, ErrTokenNotFound
	}

	if data.UsedAt != nil {
		return PasswordResetToken{}, ErrTokenAlreadyUsed
	}

	if time.Now().After(data.ExpireAt) {
		return PasswordResetToken{}, ErrTokenExpired
	}

	return PasswordResetToken{
		ID:      data.ID,
		LoginID: data.LoginID,
	}, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used
func (r *InMemoryLoginRepository) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, ok := r.passwordResetTokens[token]
	if !ok {
		return ErrTokenNotFound
	}

	now := time.Now()
	data.UsedAt = &now
	r.passwordResetTokens[token] = data
	return nil
}

// ExpirePasswordResetToken expires all password reset tokens for a login
func (r *InMemoryLoginRepository) ExpirePasswordResetToken(ctx context.Context, loginID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for token, data := range r.passwordResetTokens {
		if data.LoginID == loginID {
			data.ExpireAt = time.Now().Add(-time.Hour)
			r.passwordResetTokens[token] = data
		}
	}
	return nil
}

// InitPasswordByUsername initializes a password reset by username
func (r *InMemoryLoginRepository) InitPasswordByUsername(ctx context.Context, username string, usernameValid bool) (uuid.UUID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !usernameValid {
		return uuid.Nil, ErrLoginNotFound
	}

	loginID, ok := r.loginsByUsername[username]
	if !ok {
		return uuid.Nil, ErrLoginNotFound
	}
	return loginID, nil
}

// UpdatePasswordResetRequired updates the password reset required flag
func (r *InMemoryLoginRepository) UpdatePasswordResetRequired(ctx context.Context, loginID uuid.UUID, required bool) error {
	// Not tracked in current LoginEntity - no-op for in-memory
	return nil
}

// AddPasswordToHistory adds a password to the history
func (r *InMemoryLoginRepository) AddPasswordToHistory(ctx context.Context, arg PasswordToHistoryParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := PasswordHistoryEntry{
		ID:              uuid.New(),
		LoginID:         arg.LoginID,
		PasswordHash:    arg.PasswordHash,
		PasswordVersion: arg.PasswordVersion,
		CreatedAt:       time.Now(),
	}

	r.passwordHistory[arg.LoginID] = append(r.passwordHistory[arg.LoginID], entry)
	return nil
}

// GetPasswordHistory gets the password history for a login
func (r *InMemoryLoginRepository) GetPasswordHistory(ctx context.Context, arg PasswordHistoryParams) ([]PasswordHistoryEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	history := r.passwordHistory[arg.LoginID]
	if int32(len(history)) > arg.Limit {
		return history[:arg.Limit], nil
	}
	return history, nil
}

// RecordLoginAttempt records a login attempt
func (r *InMemoryLoginRepository) RecordLoginAttempt(ctx context.Context, attempt LoginAttempt) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if attempt.LoginID.Valid {
		r.loginAttempts[attempt.LoginID.UUID] = append(r.loginAttempts[attempt.LoginID.UUID], attempt)
	}
	return nil
}

// GetRecentFailedAttempts returns the number of failed login attempts since the given time
func (r *InMemoryLoginRepository) GetRecentFailedAttempts(ctx context.Context, loginID uuid.UUID, since time.Time) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, attempt := range r.loginAttempts[loginID] {
		if !attempt.Success && attempt.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

// IsAccountLocked checks if an account is locked
func (r *InMemoryLoginRepository) IsAccountLocked(ctx context.Context, loginID uuid.UUID) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[loginID]
	if !ok {
		return false, ErrLoginNotFound
	}

	if login.LockedUntil.IsZero() {
		return false, nil
	}
	return time.Now().Before(login.LockedUntil), nil
}

// IncrementFailedLoginAttempts increments the failed login attempts for a login
func (r *InMemoryLoginRepository) IncrementFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[loginID]
	if !ok {
		return ErrLoginNotFound
	}

	login.FailedLoginAttempts++
	login.LastFailedAttemptAt = time.Now()
	r.logins[loginID] = login
	return nil
}

// LockAccount locks an account
func (r *InMemoryLoginRepository) LockAccount(ctx context.Context, loginID uuid.UUID, lockDuration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[loginID]
	if !ok {
		return ErrLoginNotFound
	}

	login.LockedUntil = time.Now().Add(lockDuration)
	r.logins[loginID] = login
	return nil
}

// ResetFailedLoginAttempts resets the failed login attempts for a login
func (r *InMemoryLoginRepository) ResetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[loginID]
	if !ok {
		return ErrLoginNotFound
	}

	login.FailedLoginAttempts = 0
	login.LastFailedAttemptAt = time.Time{}
	login.LockedUntil = time.Time{}
	r.logins[loginID] = login
	return nil
}

// GetFailedLoginAttempts gets the failed login attempts for a login
func (r *InMemoryLoginRepository) GetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) (int32, time.Time, time.Time, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[loginID]
	if !ok {
		return 0, time.Time{}, time.Time{}, ErrLoginNotFound
	}

	return login.FailedLoginAttempts, login.LastFailedAttemptAt, login.LockedUntil, nil
}

// SetPasswordlessFlag sets whether a login uses passwordless authentication
func (r *InMemoryLoginRepository) SetPasswordlessFlag(ctx context.Context, loginID uuid.UUID, isPasswordless bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	login, ok := r.logins[loginID]
	if !ok {
		return ErrLoginNotFound
	}

	login.IsPasswordless = isPasswordless
	r.logins[loginID] = login
	return nil
}

// IsPasswordlessLogin checks if a login uses passwordless authentication
func (r *InMemoryLoginRepository) IsPasswordlessLogin(ctx context.Context, loginID uuid.UUID) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	login, ok := r.logins[loginID]
	if !ok {
		return false, ErrLoginNotFound
	}
	return login.IsPasswordless, nil
}

// GenerateMagicLinkToken generates a magic link token
func (r *InMemoryLoginRepository) GenerateMagicLinkToken(ctx context.Context, loginID uuid.UUID, token string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.magicLinkTokens[token] = magicLinkData{
		ID:        uuid.New(),
		LoginID:   loginID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
	return nil
}

// ValidateMagicLinkToken validates a magic link token
func (r *InMemoryLoginRepository) ValidateMagicLinkToken(ctx context.Context, token string) (uuid.UUID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	data, ok := r.magicLinkTokens[token]
	if !ok {
		return uuid.Nil, ErrTokenNotFound
	}

	if data.UsedAt != nil {
		return uuid.Nil, ErrTokenAlreadyUsed
	}

	if time.Now().After(data.ExpiresAt) {
		return uuid.Nil, ErrTokenExpired
	}

	return data.LoginID, nil
}

// MarkMagicLinkTokenUsed marks a magic link token as used
func (r *InMemoryLoginRepository) MarkMagicLinkTokenUsed(ctx context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, ok := r.magicLinkTokens[token]
	if !ok {
		return ErrTokenNotFound
	}

	now := time.Now()
	data.UsedAt = &now
	r.magicLinkTokens[token] = data
	return nil
}

// WithTx returns the same repository (no-op for in-memory)
func (r *InMemoryLoginRepository) WithTx(tx interface{}) LoginRepository {
	return r
}

// SeedLogin adds a login directly (for testing/initialization)
func (r *InMemoryLoginRepository) SeedLogin(login LoginEntity, email string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logins[login.ID] = login
	if login.UsernameValid {
		r.loginsByUsername[login.Username] = login.ID
	}
	if email != "" {
		r.loginsByEmail[email] = append(r.loginsByEmail[email], login.ID)
	}
}

// CreateLogin creates a new login (helper for testing/initialization)
func (r *InMemoryLoginRepository) CreateLogin(username string, password []byte, email string) LoginEntity {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	login := LoginEntity{
		ID:            uuid.New(),
		Username:      username,
		UsernameValid: username != "",
		Password:      password,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	r.logins[login.ID] = login
	if login.UsernameValid {
		r.loginsByUsername[username] = login.ID
	}
	if email != "" {
		r.loginsByEmail[email] = append(r.loginsByEmail[email], login.ID)
	}

	return login
}
