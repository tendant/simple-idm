package logins

import (
	"context"
	"database/sql"
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
func (s *LoginsService) GetLogin(ctx context.Context, id uuid.UUID) (*LoginModel, error) {
	login, err := s.loginsRepo.GetLogin(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get login: %w", err)
	}
	result := FromDBLogin(&login)
	return &result, nil
}

// ListLogins retrieves a list of logins with pagination
func (s *LoginsService) ListLogins(ctx context.Context, limit, offset int32) ([]LoginModel, int64, error) {
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

	result := FromDBLogins(logins)
	return result, count, nil
}

// SearchLogins searches for logins by username
func (s *LoginsService) SearchLogins(ctx context.Context, search string, limit, offset int32) ([]LoginModel, error) {
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
	result := FromDBLogins(logins)
	return result, nil
}

// CreateLogin creates a new login
func (s *LoginsService) CreateLogin(ctx context.Context, request LoginCreateRequest, createdBy string) (*LoginModel, error) {
	// Convert username to sql.NullString
	usernameSQL := sql.NullString{
		String: request.Username,
		Valid:  true,
	}

	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, usernameSQL)
	if err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
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

	result := FromDBLogin(&login)
	return &result, nil
}

// UpdateLogin updates a login's username
func (s *LoginsService) UpdateLogin(ctx context.Context, id uuid.UUID, request LoginUpdateRequest) (*LoginModel, error) {
	// Prepare update parameters
	params := loginsdb.UpdateLoginParams{
		ID: id,
	}

	// Set username if provided
	if request.Username != nil {
		params.Username = sql.NullString{
			String: *request.Username,
			Valid:  true,
		}
	}

	// Update username
	login, err := s.loginsRepo.UpdateLogin(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update login: %w", err)
	}

	result := FromDBLogin(&login)
	return &result, nil
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
func (s *LoginsService) UpdatePassword(ctx context.Context, id uuid.UUID, request PasswordUpdateRequest) (*LoginModel, error) {
	// Verify current password
	valid, err := s.VerifyPassword(ctx, id, request.CurrentPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to verify current password: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("current password is incorrect")
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
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

	result := FromDBLogin(&login)
	return &result, nil
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
