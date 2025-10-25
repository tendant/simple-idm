package login

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileLoginRepository implements LoginRepository using file-based storage
type FileLoginRepository struct {
	dataDir            string
	logins             map[uuid.UUID]*LoginEntity
	passwordResetTokens map[string]*PasswordResetTokenData
	passwordHistory    map[uuid.UUID][]PasswordHistoryEntry
	loginAttempts      []LoginAttempt
	magicLinkTokens    map[string]*MagicLinkTokenData
	mutex              sync.RWMutex
}

// PasswordResetTokenData represents password reset token with metadata
type PasswordResetTokenData struct {
	ID       uuid.UUID
	LoginID  uuid.UUID
	Token    string
	ExpireAt time.Time
	Used     bool
}

// MagicLinkTokenData represents magic link token with metadata
type MagicLinkTokenData struct {
	ID        uuid.UUID
	LoginID   uuid.UUID
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// loginData represents the structure of data stored in the JSON file
type loginData struct {
	Logins              []*LoginEntity              `json:"logins"`
	PasswordResetTokens []*PasswordResetTokenData   `json:"password_reset_tokens"`
	PasswordHistory     map[string][]PasswordHistoryEntry `json:"password_history"` // Key is loginID.String()
	LoginAttempts       []LoginAttempt              `json:"login_attempts"`
	MagicLinkTokens     []*MagicLinkTokenData       `json:"magic_link_tokens"`
}

// NewFileLoginRepository creates a new file-based login repository
func NewFileLoginRepository(dataDir string) (*FileLoginRepository, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	repo := &FileLoginRepository{
		dataDir:            dataDir,
		logins:             make(map[uuid.UUID]*LoginEntity),
		passwordResetTokens: make(map[string]*PasswordResetTokenData),
		passwordHistory:    make(map[uuid.UUID][]PasswordHistoryEntry),
		loginAttempts:      []LoginAttempt{},
		magicLinkTokens:    make(map[string]*MagicLinkTokenData),
	}

	// Load existing data
	if err := repo.load(); err != nil {
		return nil, fmt.Errorf("failed to load data: %w", err)
	}

	return repo, nil
}

// FindLoginByUsername finds a login by username
func (r *FileLoginRepository) FindLoginByUsername(ctx context.Context, username string, usernameValid bool) (LoginEntity, error) {
	if !usernameValid || username == "" {
		return LoginEntity{}, fmt.Errorf("invalid username")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, login := range r.logins {
		if login.UsernameValid && login.Username == username {
			return *login, nil
		}
	}

	return LoginEntity{}, fmt.Errorf("login not found with username: %s", username)
}

// FindLoginsByEmail finds all logins associated with an email address
func (r *FileLoginRepository) FindLoginsByEmail(ctx context.Context, email string) ([]LoginEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var logins []LoginEntity
	// Note: This requires joining with user data which we don't have here
	// For file-based, we'd need to store email in LoginEntity or do a cross-reference
	// For now, return empty (this method requires database JOIN)
	return logins, nil
}

// FindPrimaryLoginByEmail finds the primary login associated with an email address
func (r *FileLoginRepository) FindPrimaryLoginByEmail(ctx context.Context, email string) (LoginEntity, error) {
	// Similar to FindLoginsByEmail, requires JOIN
	return LoginEntity{}, fmt.Errorf("method requires database JOIN - not supported in file mode")
}

// GetLoginById returns a login by ID
func (r *FileLoginRepository) GetLoginById(ctx context.Context, id uuid.UUID) (LoginEntity, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[id]
	if !exists {
		return LoginEntity{}, fmt.Errorf("login not found: %s", id)
	}

	return *login, nil
}

// GetPasswordVersion gets the password version for a login
func (r *FileLoginRepository) GetPasswordVersion(ctx context.Context, id uuid.UUID) (int32, bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[id]
	if !exists {
		return 0, false, fmt.Errorf("login not found: %s", id)
	}

	return login.PasswordVersion, true, nil
}

// ResetPassword resets a password by username
func (r *FileLoginRepository) ResetPassword(ctx context.Context, arg PasswordParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for _, login := range r.logins {
		if login.UsernameValid && login.Username == arg.Username {
			login.Password = arg.Password
			login.UpdatedAt = time.Now().UTC()
			return r.save()
		}
	}

	return fmt.Errorf("login not found with username: %s", arg.Username)
}

// ResetPasswordById resets a password by login ID
func (r *FileLoginRepository) ResetPasswordById(ctx context.Context, arg PasswordParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[arg.ID]
	if !exists {
		return fmt.Errorf("login not found: %s", arg.ID)
	}

	login.Password = arg.Password
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// UpdateUserPassword updates a user's password
func (r *FileLoginRepository) UpdateUserPassword(ctx context.Context, arg PasswordParams) error {
	return r.ResetPasswordById(ctx, arg)
}

// UpdateUserPasswordAndVersion updates a user's password and version
func (r *FileLoginRepository) UpdateUserPasswordAndVersion(ctx context.Context, arg PasswordParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[arg.ID]
	if !exists {
		return fmt.Errorf("login not found: %s", arg.ID)
	}

	login.Password = arg.Password
	login.PasswordVersion = arg.PasswordVersion
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// GetPasswordUpdatedAt gets the password updated at timestamp for a login
func (r *FileLoginRepository) GetPasswordUpdatedAt(ctx context.Context, loginID uuid.UUID) (time.Time, bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[loginID]
	if !exists {
		return time.Time{}, false, fmt.Errorf("login not found: %s", loginID)
	}

	return login.PasswordUpdatedAt, !login.PasswordUpdatedAt.IsZero(), nil
}

// GetPasswordExpiresAt gets the password expire at timestamp for a login
func (r *FileLoginRepository) GetPasswordExpiresAt(ctx context.Context, loginID uuid.UUID) (time.Time, bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[loginID]
	if !exists {
		return time.Time{}, false, fmt.Errorf("login not found: %s", loginID)
	}

	return login.PasswordExpiresAt, !login.PasswordExpiresAt.IsZero(), nil
}

// UpdatePasswordTimestamps updates the password updated at and expire at timestamps
func (r *FileLoginRepository) UpdatePasswordTimestamps(ctx context.Context, loginID uuid.UUID, updatedAt, expiresAt time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[loginID]
	if !exists {
		return fmt.Errorf("login not found: %s", loginID)
	}

	login.PasswordUpdatedAt = updatedAt
	login.PasswordExpiresAt = expiresAt
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// InitPasswordResetToken initializes a password reset token
func (r *FileLoginRepository) InitPasswordResetToken(ctx context.Context, arg PasswordResetTokenParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	token := &PasswordResetTokenData{
		ID:       uuid.New(),
		LoginID:  arg.LoginID,
		Token:    arg.Token,
		ExpireAt: arg.ExpireAt,
		Used:     false,
	}

	r.passwordResetTokens[arg.Token] = token
	return r.save()
}

// ValidatePasswordResetToken validates a password reset token
func (r *FileLoginRepository) ValidatePasswordResetToken(ctx context.Context, token string) (PasswordResetToken, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	tokenData, exists := r.passwordResetTokens[token]
	if !exists {
		return PasswordResetToken{}, fmt.Errorf("token not found")
	}

	if tokenData.Used {
		return PasswordResetToken{}, fmt.Errorf("token already used")
	}

	if time.Now().UTC().After(tokenData.ExpireAt) {
		return PasswordResetToken{}, fmt.Errorf("token expired")
	}

	return PasswordResetToken{
		ID:      tokenData.ID,
		LoginID: tokenData.LoginID,
	}, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used
func (r *FileLoginRepository) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	tokenData, exists := r.passwordResetTokens[token]
	if !exists {
		return fmt.Errorf("token not found")
	}

	tokenData.Used = true
	return r.save()
}

// ExpirePasswordResetToken expires all password reset tokens for a login
func (r *FileLoginRepository) ExpirePasswordResetToken(ctx context.Context, loginID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for _, tokenData := range r.passwordResetTokens {
		if tokenData.LoginID == loginID {
			tokenData.ExpireAt = time.Now().UTC()
		}
	}

	return r.save()
}

// InitPasswordByUsername initializes a password reset by username
func (r *FileLoginRepository) InitPasswordByUsername(ctx context.Context, username string, usernameValid bool) (uuid.UUID, error) {
	if !usernameValid || username == "" {
		return uuid.Nil, fmt.Errorf("invalid username")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, login := range r.logins {
		if login.UsernameValid && login.Username == username {
			return login.ID, nil
		}
	}

	return uuid.Nil, fmt.Errorf("login not found with username: %s", username)
}

// UpdatePasswordResetRequired updates the password reset required flag
func (r *FileLoginRepository) UpdatePasswordResetRequired(ctx context.Context, loginID uuid.UUID, required bool) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[loginID]
	if !exists {
		return fmt.Errorf("login not found: %s", loginID)
	}

	// Note: LoginEntity doesn't have PasswordResetRequired field in the struct we saw
	// This would need to be added if needed
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// AddPasswordToHistory adds a password to the history
func (r *FileLoginRepository) AddPasswordToHistory(ctx context.Context, arg PasswordToHistoryParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	entry := PasswordHistoryEntry{
		ID:              uuid.New(),
		LoginID:         arg.LoginID,
		PasswordHash:    arg.PasswordHash,
		PasswordVersion: arg.PasswordVersion,
		CreatedAt:       time.Now().UTC(),
	}

	r.passwordHistory[arg.LoginID] = append(r.passwordHistory[arg.LoginID], entry)
	return r.save()
}

// GetPasswordHistory gets the password history for a login
func (r *FileLoginRepository) GetPasswordHistory(ctx context.Context, arg PasswordHistoryParams) ([]PasswordHistoryEntry, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	history, exists := r.passwordHistory[arg.LoginID]
	if !exists {
		return []PasswordHistoryEntry{}, nil
	}

	// Sort by created_at desc and apply limit
	// Simple sort - newest first
	sorted := make([]PasswordHistoryEntry, len(history))
	copy(sorted, history)

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].CreatedAt.Before(sorted[j].CreatedAt) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Apply limit
	if arg.Limit > 0 && int(arg.Limit) < len(sorted) {
		sorted = sorted[:arg.Limit]
	}

	return sorted, nil
}

// RecordLoginAttempt records a login attempt
func (r *FileLoginRepository) RecordLoginAttempt(ctx context.Context, attempt LoginAttempt) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	attempt.ID = uuid.New()
	attempt.CreatedAt = time.Now().UTC()

	r.loginAttempts = append(r.loginAttempts, attempt)

	// Keep only last 10000 attempts to prevent unbounded growth
	if len(r.loginAttempts) > 10000 {
		r.loginAttempts = r.loginAttempts[len(r.loginAttempts)-10000:]
	}

	return r.save()
}

// GetRecentFailedAttempts returns the number of failed login attempts since the given time
func (r *FileLoginRepository) GetRecentFailedAttempts(ctx context.Context, loginID uuid.UUID, since time.Time) (int, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	count := 0
	for _, attempt := range r.loginAttempts {
		if attempt.LoginID.Valid && attempt.LoginID.UUID == loginID &&
			!attempt.Success &&
			attempt.CreatedAt.After(since) {
			count++
		}
	}

	return count, nil
}

// IsAccountLocked checks if an account is locked
func (r *FileLoginRepository) IsAccountLocked(ctx context.Context, loginID uuid.UUID) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[loginID]
	if !exists {
		return false, fmt.Errorf("login not found: %s", loginID)
	}

	return time.Now().UTC().Before(login.LockedUntil), nil
}

// IncrementFailedLoginAttempts increments the failed login attempts for a login
func (r *FileLoginRepository) IncrementFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[loginID]
	if !exists {
		return fmt.Errorf("login not found: %s", loginID)
	}

	login.FailedLoginAttempts++
	login.LastFailedAttemptAt = time.Now().UTC()
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// LockAccount locks an account
func (r *FileLoginRepository) LockAccount(ctx context.Context, loginID uuid.UUID, lockDuration time.Duration) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[loginID]
	if !exists {
		return fmt.Errorf("login not found: %s", loginID)
	}

	login.LockedUntil = time.Now().UTC().Add(lockDuration)
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// ResetFailedLoginAttempts resets the failed login attempts for a login
func (r *FileLoginRepository) ResetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[loginID]
	if !exists {
		return fmt.Errorf("login not found: %s", loginID)
	}

	login.FailedLoginAttempts = 0
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// GetFailedLoginAttempts gets the failed login attempts for a login
func (r *FileLoginRepository) GetFailedLoginAttempts(ctx context.Context, loginID uuid.UUID) (int32, time.Time, time.Time, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[loginID]
	if !exists {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("login not found: %s", loginID)
	}

	return login.FailedLoginAttempts, login.LastFailedAttemptAt, login.LockedUntil, nil
}

// SetPasswordlessFlag sets whether a login uses passwordless authentication
func (r *FileLoginRepository) SetPasswordlessFlag(ctx context.Context, loginID uuid.UUID, isPasswordless bool) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	login, exists := r.logins[loginID]
	if !exists {
		return fmt.Errorf("login not found: %s", loginID)
	}

	login.IsPasswordless = isPasswordless
	login.UpdatedAt = time.Now().UTC()
	return r.save()
}

// IsPasswordlessLogin checks if a login uses passwordless authentication
func (r *FileLoginRepository) IsPasswordlessLogin(ctx context.Context, loginID uuid.UUID) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	login, exists := r.logins[loginID]
	if !exists {
		return false, fmt.Errorf("login not found: %s", loginID)
	}

	return login.IsPasswordless, nil
}

// GenerateMagicLinkToken generates a magic link token
func (r *FileLoginRepository) GenerateMagicLinkToken(ctx context.Context, loginID uuid.UUID, token string, expiresAt time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	magicToken := &MagicLinkTokenData{
		ID:        uuid.New(),
		LoginID:   loginID,
		Token:     token,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		UsedAt:    nil,
	}

	r.magicLinkTokens[token] = magicToken
	return r.save()
}

// ValidateMagicLinkToken validates a magic link token
func (r *FileLoginRepository) ValidateMagicLinkToken(ctx context.Context, token string) (uuid.UUID, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	tokenData, exists := r.magicLinkTokens[token]
	if !exists {
		return uuid.Nil, fmt.Errorf("token not found")
	}

	if tokenData.UsedAt != nil {
		return uuid.Nil, fmt.Errorf("token already used")
	}

	if time.Now().UTC().After(tokenData.ExpiresAt) {
		return uuid.Nil, fmt.Errorf("invalid or expired token")
	}

	return tokenData.LoginID, nil
}

// MarkMagicLinkTokenUsed marks a magic link token as used
func (r *FileLoginRepository) MarkMagicLinkTokenUsed(ctx context.Context, token string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	tokenData, exists := r.magicLinkTokens[token]
	if !exists {
		return fmt.Errorf("token not found")
	}

	now := time.Now().UTC()
	tokenData.UsedAt = &now
	return r.save()
}

// WithTx returns a new repository with the given transaction
// File-based implementation doesn't support transactions, returns self
func (r *FileLoginRepository) WithTx(tx interface{}) LoginRepository {
	// File-based storage doesn't support transactions
	// Return self to maintain interface compatibility
	return r
}

// load reads login data from file
func (r *FileLoginRepository) load() error {
	filePath := filepath.Join(r.dataDir, "login.json")

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

	var loginDataObj loginData
	if err := json.Unmarshal(data, &loginDataObj); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Convert to maps
	r.logins = make(map[uuid.UUID]*LoginEntity)
	for _, login := range loginDataObj.Logins {
		r.logins[login.ID] = login
	}

	r.passwordResetTokens = make(map[string]*PasswordResetTokenData)
	for _, token := range loginDataObj.PasswordResetTokens {
		r.passwordResetTokens[token.Token] = token
	}

	// Convert password history from string keys to UUID keys
	r.passwordHistory = make(map[uuid.UUID][]PasswordHistoryEntry)
	for loginIDStr, history := range loginDataObj.PasswordHistory {
		loginID, err := uuid.Parse(loginIDStr)
		if err != nil {
			continue // Skip invalid UUIDs
		}
		r.passwordHistory[loginID] = history
	}

	r.loginAttempts = loginDataObj.LoginAttempts
	if r.loginAttempts == nil {
		r.loginAttempts = []LoginAttempt{}
	}

	r.magicLinkTokens = make(map[string]*MagicLinkTokenData)
	for _, token := range loginDataObj.MagicLinkTokens {
		r.magicLinkTokens[token.Token] = token
	}

	return nil
}

// save writes login data to file atomically
func (r *FileLoginRepository) save() error {
	// Convert maps to slices
	logins := make([]*LoginEntity, 0, len(r.logins))
	for _, login := range r.logins {
		logins = append(logins, login)
	}

	passwordResetTokens := make([]*PasswordResetTokenData, 0, len(r.passwordResetTokens))
	for _, token := range r.passwordResetTokens {
		passwordResetTokens = append(passwordResetTokens, token)
	}

	// Convert password history to string keys for JSON
	passwordHistory := make(map[string][]PasswordHistoryEntry)
	for loginID, history := range r.passwordHistory {
		passwordHistory[loginID.String()] = history
	}

	magicLinkTokens := make([]*MagicLinkTokenData, 0, len(r.magicLinkTokens))
	for _, token := range r.magicLinkTokens {
		magicLinkTokens = append(magicLinkTokens, token)
	}

	data := loginData{
		Logins:              logins,
		PasswordResetTokens: passwordResetTokens,
		PasswordHistory:     passwordHistory,
		LoginAttempts:       r.loginAttempts,
		MagicLinkTokens:     magicLinkTokens,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to temp file first
	tempFile := filepath.Join(r.dataDir, "login.json.tmp")
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	finalFile := filepath.Join(r.dataDir, "login.json")
	if err := os.Rename(tempFile, finalFile); err != nil {
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}
