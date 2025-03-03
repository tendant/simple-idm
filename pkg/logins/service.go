package logins

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"golang.org/x/crypto/bcrypt"
)

// LoginsService provides methods for managing logins
type LoginsService struct {
	loginsRepo *loginsdb.Queries
}

// NewLoginsService creates a new logins service
func NewLoginsService(loginsRepo *loginsdb.Queries) *LoginsService {
	return &LoginsService{
		loginsRepo: loginsRepo,
	}
}

// GetLogin retrieves a login by ID
func (s *LoginsService) GetLogin(ctx context.Context, id uuid.UUID) (*loginsdb.Login, error) {
	login, err := s.loginsRepo.GetLogin(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get login: %w", err)
	}
	return &login, nil
}

// ListLogins retrieves a list of logins with pagination
func (s *LoginsService) ListLogins(ctx context.Context, limit, offset int32) ([]loginsdb.Login, int64, error) {
	logins, err := s.loginsRepo.ListLogins(ctx, loginsdb.ListLoginsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list logins: %w", err)
	}

	count, err := s.loginsRepo.CountLogins(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count logins: %w", err)
	}

	return logins, count, nil
}

// SearchLogins searches for logins by username
func (s *LoginsService) SearchLogins(ctx context.Context, search string, limit, offset int32) ([]loginsdb.Login, error) {
	// Convert string to pgtype.Text
	var searchText pgtype.Text
	searchText.String = search
	searchText.Valid = true

	logins, err := s.loginsRepo.SearchLogins(ctx, loginsdb.SearchLoginsParams{
		Column1: searchText,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search logins: %w", err)
	}
	return logins, nil
}

// CreateLogin creates a new login
func (s *LoginsService) CreateLogin(ctx context.Context, username, password, createdBy string) (*loginsdb.Login, error) {
	// Convert username to sql.NullString
	usernameSQL := sql.NullString{
		String: username,
		Valid:  true,
	}

	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, usernameSQL)
	if err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Convert createdBy to sql.NullString
	createdBySQL := sql.NullString{
		String: createdBy,
		Valid:  true,
	}

	login, err := s.loginsRepo.CreateLogin(ctx, loginsdb.CreateLoginParams{
		Username:  usernameSQL,
		Password:  hashedPassword,
		CreatedBy: createdBySQL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create login: %w", err)
	}

	return &login, nil
}

// UpdateLogin updates a login's username
func (s *LoginsService) UpdateLogin(ctx context.Context, id uuid.UUID, username string) (*loginsdb.Login, error) {
	// Convert username to sql.NullString
	usernameSQL := sql.NullString{
		String: username,
		Valid:  true,
	}

	login, err := s.loginsRepo.UpdateLogin(ctx, loginsdb.UpdateLoginParams{
		ID:       id,
		Username: usernameSQL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update login: %w", err)
	}
	return &login, nil
}

// DeleteLogin soft deletes a login
func (s *LoginsService) DeleteLogin(ctx context.Context, id uuid.UUID) error {
	err := s.loginsRepo.DeleteLogin(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete login: %w", err)
	}
	return nil
}

// UpdatePassword updates a login's password
func (s *LoginsService) UpdatePassword(ctx context.Context, id uuid.UUID, password string) (*loginsdb.Login, error) {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	login, err := s.loginsRepo.UpdateLoginPassword(ctx, loginsdb.UpdateLoginPasswordParams{
		ID:       id,
		Password: hashedPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}
	return &login, nil
}

// EnableTwoFactor enables two-factor authentication for a login
func (s *LoginsService) EnableTwoFactor(ctx context.Context, id uuid.UUID, secret string) (*loginsdb.Login, error) {
	// Convert secret to pgtype.Text
	var secretText pgtype.Text
	secretText.String = secret
	secretText.Valid = true

	login, err := s.loginsRepo.EnableTwoFactor(ctx, loginsdb.EnableTwoFactorParams{
		ID:              id,
		TwoFactorSecret: secretText,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enable two-factor authentication: %w", err)
	}
	return &login, nil
}

// DisableTwoFactor disables two-factor authentication for a login
func (s *LoginsService) DisableTwoFactor(ctx context.Context, id uuid.UUID) (*loginsdb.Login, error) {
	login, err := s.loginsRepo.DisableTwoFactor(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to disable two-factor authentication: %w", err)
	}
	return &login, nil
}

// GenerateBackupCodes generates new backup codes for a login
func (s *LoginsService) GenerateBackupCodes(ctx context.Context, id uuid.UUID) ([]string, error) {
	// Generate 10 backup codes
	backupCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		// Generate 10 random bytes
		bytes := make([]byte, 10)
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}
		// Encode as base32 and take the first 10 characters
		backupCodes[i] = base64.StdEncoding.EncodeToString(bytes)[:10]
	}

	// Save backup codes to the database
	_, err := s.loginsRepo.SetTwoFactorBackupCodes(ctx, loginsdb.SetTwoFactorBackupCodesParams{
		ID:                   id,
		TwoFactorBackupCodes: backupCodes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save backup codes: %w", err)
	}

	return backupCodes, nil
}

// VerifyPassword verifies a login's password
func (s *LoginsService) VerifyPassword(ctx context.Context, id uuid.UUID, password string) (bool, error) {
	login, err := s.loginsRepo.GetLogin(ctx, id)
	if err != nil {
		return false, fmt.Errorf("failed to get login: %w", err)
	}

	err = bcrypt.CompareHashAndPassword(login.Password, []byte(password))
	if err != nil {
		return false, nil
	}

	return true, nil
}
