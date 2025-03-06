package logins

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/login/logindb"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
	"github.com/tendant/simple-idm/pkg/utils"
)

// LoginsService provides methods for managing logins
type LoginsService struct {
	loginsRepo      *loginsdb.Queries
	passwordManager *login.PasswordManager
}

// LoginsServiceOptions contains optional parameters for creating a LoginsService
type LoginsServiceOptions struct {
	PasswordPolicy *login.PasswordPolicy
}

// NewLoginsService creates a new logins service
func NewLoginsService(loginsRepo *loginsdb.Queries, loginQueries *logindb.Queries, options *LoginsServiceOptions) *LoginsService {
	// Use provided policy or default
	var policy *login.PasswordPolicy
	if options != nil && options.PasswordPolicy != nil {
		policy = options.PasswordPolicy
	} else {
		policy = login.DefaultPasswordPolicy()
	}

	// Create the policy checker
	policyChecker := login.NewDefaultPasswordPolicyChecker(policy, nil)

	// Create password manager with the policy checker
	passwordManager := login.NewPasswordManager(loginQueries, policyChecker, login.CurrentPasswordVersion)

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
	usernameSQL := utils.ToNullString(request.Username)
	createdBySQL := utils.ToNullString(createdBy)

	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, usernameSQL)
	if err == nil {
		return nil, fmt.Errorf("username already exists")
	}
	// Validate password complexity
	if err := s.passwordManager.CheckPasswordComplexity(request.Password); err != nil {
		return nil, fmt.Errorf("password does not meet complexity requirements: %w", err)
	}

	// Hash the password
	hashedPassword, err := s.passwordManager.HashPassword(request.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	login, err := s.loginsRepo.CreateLogin(ctx, loginsdb.CreateLoginParams{
		Username:  usernameSQL,
		Password:  []byte(hashedPassword),
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
	// Convert username to sql.NullString
	usernameSQL := utils.ToNullString(request.Username)
	// Check if username already exists
	_, err := s.loginsRepo.GetLoginByUsername(ctx, usernameSQL)
	if err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Prepare update parameters
	params := loginsdb.UpdateLoginParams{
		ID:       id,
		Username: usernameSQL,
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
