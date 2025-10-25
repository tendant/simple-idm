package logins

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
)

// LoginsService provides methods for managing logins
type LoginsService struct {
	loginsRepo      LoginsRepository
	passwordManager *login.PasswordManager
}

// LoginsServiceOptions contains optional parameters for creating a LoginsService
type LoginsServiceOptions struct {
	PasswordManager *login.PasswordManager
}

// NewLoginsService creates a new logins service
func NewLoginsService(loginsRepo LoginsRepository, loginQueries *logindb.Queries, options *LoginsServiceOptions) *LoginsService {
	// Use provided policy or default
	var passwordManager *login.PasswordManager
	if options != nil && options.PasswordManager != nil {
		passwordManager = options.PasswordManager
	} else {
		passwordManager = login.NewPasswordManager(loginQueries)
	}
	return &LoginsService{
		loginsRepo:      loginsRepo,
		passwordManager: passwordManager,
	}
}

// WithPasswordManager sets the password manager
func (s *LoginsService) WithPasswordManager(passwordManager *login.PasswordManager) *LoginsService {
	s.passwordManager = passwordManager
	return s
}

// GetLogin retrieves a login by ID
func (s *LoginsService) GetLogin(ctx context.Context, id uuid.UUID) (*LoginModel, error) {
	loginEntity, err := s.loginsRepo.GetLogin(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get login: %w", err)
	}
	result := FromLoginEntity(&loginEntity)
	return &result, nil
}

// ListLogins retrieves a list of logins with pagination
func (s *LoginsService) ListLogins(ctx context.Context, limit, offset int32) ([]LoginModel, int64, error) {
	loginEntities, err := s.loginsRepo.ListLogins(ctx, ListLoginsParams{
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

	result := FromLoginEntities(loginEntities)
	return result, count, nil
}

// SearchLogins searches for logins by username
func (s *LoginsService) SearchLogins(ctx context.Context, search string, limit, offset int32) ([]LoginModel, error) {
	loginEntities, err := s.loginsRepo.SearchLogins(ctx, SearchLoginsParams{
		Query:  search,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search logins: %w", err)
	}
	result := FromLoginEntities(loginEntities)
	return result, nil
}

// CreateLogin creates a new login
func (s *LoginsService) CreateLogin(ctx context.Context, request LoginCreateRequest, createdBy string) (*LoginModel, error) {
	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, request.Username, request.Username != "")
	if err == nil {
		return nil, ErrUsernameAlreadyExists{Username: request.Username}
	}
	// Validate password complexity
	if err := s.passwordManager.CheckPasswordComplexity(request.Password); err != nil {
		return nil, ErrPasswordComplexity{Details: err.Error()}
	}

	// Hash the password
	hashedPassword, err := s.passwordManager.HashPassword(request.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	loginEntity, err := s.loginsRepo.CreateLogin(ctx, CreateLoginParams{
		Username:       request.Username,
		UsernameValid:  request.Username != "",
		Password:       []byte(hashedPassword),
		CreatedBy:      createdBy,
		CreatedByValid: createdBy != "",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create login: %w", err)
	}

	result := FromLoginEntity(&loginEntity)
	return &result, nil
}

// UpdateLogin updates a login's username
func (s *LoginsService) UpdateLogin(ctx context.Context, id uuid.UUID, request LoginUpdateRequest) (*LoginModel, error) {
	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, request.Username, request.Username != "")
	if err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Update username
	loginEntity, err := s.loginsRepo.UpdateLogin(ctx, UpdateLoginParams{
		ID:            id,
		Username:      request.Username,
		UsernameValid: request.Username != "",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update login: %w", err)
	}

	result := FromLoginEntity(&loginEntity)
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

// CreateLoginWithoutPassword creates a new login without a password
// This is useful for passwordless accounts where authentication is done via magic links
func (s *LoginsService) CreateLoginWithoutPassword(ctx context.Context, username string, createdBy string) (*LoginModel, error) {
	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, username, username != "")
	if err == nil {
		return nil, ErrUsernameAlreadyExists{Username: username}
	}

	// Create login with empty password
	loginEntity, err := s.loginsRepo.CreateLogin(ctx, CreateLoginParams{
		Username:       username,
		UsernameValid:  username != "",
		Password:       []byte{}, // Empty password
		CreatedBy:      createdBy,
		CreatedByValid: createdBy != "",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create login: %w", err)
	}

	result := FromLoginEntity(&loginEntity)
	return &result, nil
}
