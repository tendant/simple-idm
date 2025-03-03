package logins

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"golang.org/x/crypto/bcrypt"
)

// LoginService provides methods for managing logins
type LoginService struct {
	db        *pgxpool.Pool
	loginRepo *loginsdb.Queries
}

// NewLoginService creates a new login service
func NewLoginService(db *pgxpool.Pool) *LoginService {
	return &LoginService{
		db:        db,
		loginRepo: loginsdb.New(db),
	}
}

// GetLogin retrieves a login by ID
func (s *LoginService) GetLogin(ctx context.Context, id uuid.UUID) (*loginsdb.Login, error) {
	login, err := s.loginRepo.GetLogin(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get login: %w", err)
	}
	return &login, nil
}

// ListLogins retrieves a list of logins with pagination
func (s *LoginService) ListLogins(ctx context.Context, limit, offset int32) ([]loginsdb.Login, int64, error) {
	logins, err := s.loginRepo.ListLogins(ctx, loginsdb.ListLoginsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list logins: %w", err)
	}

	count, err := s.loginRepo.CountLogins(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count logins: %w", err)
	}

	return logins, count, nil
}

// SearchLogins searches for logins by username
func (s *LoginService) SearchLogins(ctx context.Context, search string, limit, offset int32) ([]loginsdb.Login, error) {
	logins, err := s.loginRepo.SearchLogins(ctx, loginsdb.SearchLoginsParams{
		Column1: search,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search logins: %w", err)
	}
	return logins, nil
}

// CreateLogin creates a new login
func (s *LoginService) CreateLogin(ctx context.Context, username, password, createdBy string) (*loginsdb.Login, error) {
	// Check if username already exists
	_, err := s.loginRepo.GetLoginByUsername(ctx, username)
	if err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	login, err := s.loginRepo.CreateLogin(ctx, loginsdb.CreateLoginParams{
		Username:  username,
		Password:  hashedPassword,
		CreatedBy: &createdBy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create login: %w", err)
	}

	return &login, nil
}

// UpdateLogin updates a login's username
func (s *LoginService) UpdateLogin(ctx context.Context, id uuid.UUID, username string) (*loginsdb.Login, error) {
	login, err := s.loginRepo.UpdateLogin(ctx, loginsdb.UpdateLoginParams{
		ID:       id,
		Username: username,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update login: %w", err)
	}
	return &login, nil
}

// DeleteLogin soft deletes a login
func (s *LoginService) DeleteLogin(ctx context.Context, id uuid.UUID) error {
	err := s.loginRepo.DeleteLogin(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete login: %w", err)
	}
	return nil
}

// UpdatePassword updates a login's password
func (s *LoginService) UpdatePassword(ctx context.Context, id uuid.UUID, password string) (*loginsdb.Login, error) {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	login, err := s.loginRepo.UpdateLoginPassword(ctx, loginsdb.UpdateLoginPasswordParams{
		ID:       id,
		Password: hashedPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}
	return &login, nil
}

// EnableTwoFactor enables two-factor authentication for a login
func (s *LoginService) EnableTwoFactor(ctx context.Context, id uuid.UUID, secret string) (*loginsdb.Login, error) {
	login, err := s.loginRepo.EnableTwoFactor(ctx, loginsdb.EnableTwoFactorParams{
		ID:              id,
		TwoFactorSecret: secret,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enable two-factor authentication: %w", err)
	}
	return &login, nil
}

// DisableTwoFactor disables two-factor authentication for a login
func (s *LoginService) DisableTwoFactor(ctx context.Context, id uuid.UUID) (*loginsdb.Login, error) {
	login, err := s.loginRepo.DisableTwoFactor(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to disable two-factor authentication: %w", err)
	}
	return &login, nil
}

// GenerateBackupCodes generates new backup codes for a login
func (s *LoginService) GenerateBackupCodes(ctx context.Context, id uuid.UUID) ([]string, error) {
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
	_, err := s.loginRepo.SetTwoFactorBackupCodes(ctx, loginsdb.SetTwoFactorBackupCodesParams{
		ID:                  id,
		TwoFactorBackupCodes: backupCodes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save backup codes: %w", err)
	}

	return backupCodes, nil
}

// VerifyPassword verifies a login's password
func (s *LoginService) VerifyPassword(ctx context.Context, id uuid.UUID, password string) (bool, error) {
	login, err := s.loginRepo.GetLogin(ctx, id)
	if err != nil {
		return false, fmt.Errorf("failed to get login: %w", err)
	}

	err = bcrypt.CompareHashAndPassword(login.Password, []byte(password))
	if err != nil {
		return false, nil
	}

	return true, nil
}
