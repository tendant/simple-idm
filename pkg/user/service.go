package user

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/iam/iamdb"
	"github.com/tendant/simple-idm/pkg/logins"
)

// UserService provides user management operations
type UserService struct {
	iamService    *iam.IamService
	loginsService *logins.LoginsService
	iamQueries    *iamdb.Queries
}

// NewUserService creates a new user service
func NewUserService(iamService *iam.IamService, loginsService *logins.LoginsService, iamQueries *iamdb.Queries) *UserService {
	return &UserService{
		iamService:    iamService,
		loginsService: loginsService,
		iamQueries:    iamQueries,
	}
}

// CreateAdminUserOptions contains options for creating an admin user
type CreateAdminUserOptions struct {
	Username string // Default: "super"
	Email    string // Default: "{username}@example.com"
}

// CreateAdminUserResult contains the result of creating an admin user
type CreateAdminUserResult struct {
	UserID      uuid.UUID `json:"user_id"`
	LoginID     uuid.UUID `json:"login_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Password    string    `json:"password"`
	AdminRoleID uuid.UUID `json:"admin_role_id"`
}

// CreateAdminUser creates an admin user with the specified options
func (s *UserService) CreateAdminUser(ctx context.Context, options CreateAdminUserOptions) (*CreateAdminUserResult, error) {
	// Set defaults
	username := options.Username
	if username == "" {
		username = "super"
	}

	email := options.Email
	if email == "" {
		email = fmt.Sprintf("%s@example.com", username)
	}

	slog.Info("Creating admin user", "username", username, "email", email)

	// Step 1: Create or find admin role
	adminRoleID, err := s.ensureAdminRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure admin role exists: %w", err)
	}
	slog.Info("Admin role ensured", "role_id", adminRoleID)

	// Step 2: Generate secure password
	password, err := s.generateSecurePassword()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure password: %w", err)
	}

	// Step 3: Create login record
	loginModel, err := s.loginsService.CreateLogin(ctx, logins.LoginCreateRequest{
		Username: username,
		Password: password,
	}, "system")
	if err != nil {
		return nil, fmt.Errorf("failed to create login: %w", err)
	}
	slog.Info("Login created", "login_id", loginModel.ID, "username", username)

	// Step 4: Create user record with admin role
	userWithRoles, err := s.iamService.CreateUser(ctx, email, username, "", []uuid.UUID{adminRoleID}, loginModel.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	slog.Info("User created with admin role", "user_id", userWithRoles.User.ID, "email", email)

	// Parse login ID string to UUID for result
	loginUUID, err := uuid.Parse(loginModel.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse login ID: %w", err)
	}

	result := &CreateAdminUserResult{
		UserID:      userWithRoles.User.ID,
		LoginID:     loginUUID,
		Username:    username,
		Email:       email,
		Password:    password,
		AdminRoleID: adminRoleID,
	}

	// Step 5: Display password in console
	s.displayPasswordInConsole(result)

	return result, nil
}

// ensureAdminRole creates the admin role if it doesn't exist, or returns its ID if it does
func (s *UserService) ensureAdminRole(ctx context.Context) (uuid.UUID, error) {
	// Try to find existing admin role
	roles, err := s.iamQueries.FindRoles(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to find existing roles: %w", err)
	}

	// Check if admin role already exists
	for _, role := range roles {
		if strings.ToLower(role.Name) == "admin" {
			slog.Info("Admin role already exists", "role_id", role.ID)
			return role.ID, nil
		}
	}

	// Create admin role if it doesn't exist
	adminRoleID, err := s.iamQueries.CreateRole(ctx, "admin")
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create admin role: %w", err)
	}

	slog.Info("Admin role created", "role_id", adminRoleID)
	return adminRoleID, nil
}

// generateSecurePassword generates a cryptographically secure password
func (s *UserService) generateSecurePassword() (string, error) {
	const (
		length    = 16
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		symbols   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		allChars  = lowercase + uppercase + digits + symbols
	)

	password := make([]byte, length)

	// Ensure at least one character from each category
	categories := []string{lowercase, uppercase, digits, symbols}
	for i, category := range categories {
		char, err := s.randomCharFromString(category)
		if err != nil {
			return "", fmt.Errorf("failed to generate character from category: %w", err)
		}
		password[i] = char
	}

	// Fill the rest with random characters from all categories
	for i := len(categories); i < length; i++ {
		char, err := s.randomCharFromString(allChars)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		password[i] = char
	}

	// Shuffle the password to avoid predictable patterns
	s.shuffleBytes(password)

	return string(password), nil
}

// randomCharFromString returns a random character from the given string
func (s *UserService) randomCharFromString(str string) (byte, error) {
	if len(str) == 0 {
		return 0, fmt.Errorf("empty string provided")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(str))))
	if err != nil {
		return 0, err
	}

	return str[n.Int64()], nil
}

// shuffleBytes randomly shuffles the bytes in the slice
func (s *UserService) shuffleBytes(bytes []byte) {
	for i := len(bytes) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// Fallback to a simple swap if crypto/rand fails
			j = big.NewInt(int64(i))
		}
		bytes[i], bytes[j.Int64()] = bytes[j.Int64()], bytes[i]
	}
}

// displayPasswordInConsole displays the generated password prominently in the console
func (s *UserService) displayPasswordInConsole(result *CreateAdminUserResult) {
	border := strings.Repeat("=", 80)
	fmt.Printf("\n%s\n", border)
	fmt.Printf("🔐 ADMIN USER CREATED SUCCESSFULLY\n")
	fmt.Printf("%s\n", border)
	fmt.Printf("Username:     %s\n", result.Username)
	fmt.Printf("Email:        %s\n", result.Email)
	fmt.Printf("Password:     %s\n", result.Password)
	fmt.Printf("User ID:      %s\n", result.UserID)
	fmt.Printf("Login ID:     %s\n", result.LoginID)
	fmt.Printf("Admin Role:   %s\n", result.AdminRoleID)
	fmt.Printf("%s\n", border)
	fmt.Printf("⚠️  IMPORTANT SECURITY NOTICE:\n")
	fmt.Printf("   • Store this password securely\n")
	fmt.Printf("   • Change the password after first login\n")
	fmt.Printf("   • This password will not be displayed again\n")
	fmt.Printf("%s\n\n", border)

	// Also log the creation (without password)
	slog.Info("Admin user creation completed",
		"username", result.Username,
		"email", result.Email,
		"user_id", result.UserID,
		"login_id", result.LoginID,
		"admin_role_id", result.AdminRoleID,
	)
}
