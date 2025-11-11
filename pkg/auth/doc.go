// Package auth provides authentication services for password verification and management.
//
// This package handles password complexity validation, password matching, and password
// updates with support for multiple storage backends through repository interfaces.
//
// # Overview
//
// The auth package provides:
//   - Password complexity validation
//   - Password matching and verification
//   - Password updates
//   - Repository pattern for database abstraction
//   - Support for PostgreSQL and custom backends
//
// # Basic Usage
//
// Creating and using the auth service:
//
//	import (
//		"github.com/tendant/simple-idm/pkg/auth"
//		"github.com/tendant/simple-idm/pkg/login"
//	)
//
//	// Create repositories
//	authRepo := auth.NewPostgresAuthRepository(db)
//	loginService := login.NewLoginService(loginQueries)
//
//	// Create auth service
//	authService := auth.NewAuthLoginService(authRepo, loginService)
//
//	// Or with password complexity requirements
//	authService := auth.NewAuthLoginService(
//		authRepo,
//		loginService,
//		auth.WithPwdComplex(auth.PasswordComplexity{
//			RequiredLength:          12,
//			RequiredDigit:           true,
//			RequiredLowercase:       true,
//			RequiredUppercase:       true,
//			RequiredNonAlphanumeric: true,
//		}),
//	)
//
// # Password Complexity Validation
//
// Validate passwords against complexity requirements:
//
//	// Verify password meets complexity requirements
//	err := authService.VerifyPasswordComplexity(ctx, "MyP@ssw0rd123")
//	if err != nil {
//		// Password doesn't meet requirements
//		fmt.Println(err) // "password must have at least one digit"
//		return err
//	}
//
//	// Configure complexity requirements
//	complexity := auth.PasswordComplexity{
//		RequiredLength:          8,   // Minimum 8 characters
//		RequiredDigit:           true, // Must contain digits
//		RequiredLowercase:       true, // Must contain lowercase
//		RequiredUppercase:       true, // Must contain uppercase
//		RequiredNonAlphanumeric: true, // Must contain special characters
//	}
//
//	authService := auth.NewAuthLoginService(
//		repo,
//		loginService,
//		auth.WithPwdComplex(complexity),
//	)
//
// # Password Matching
//
// Verify user passwords:
//
//	// Match password for a user
//	matched, err := authService.MatchPasswordByUuids(ctx, auth.MatchPassParam{
//		UserUuid: userID,
//		Password: "user-entered-password",
//	})
//	if err != nil {
//		return err
//	}
//	if !matched {
//		return errors.New("invalid password")
//	}
//
//	// Use in login flow
//	func (h *LoginHandler) Login(ctx context.Context, email, password string) (*Token, error) {
//		// Get user by email
//		user, err := h.iamService.GetUserByEmail(ctx, email)
//		if err != nil {
//			return nil, err
//		}
//
//		// Verify password
//		matched, err := h.authService.MatchPasswordByUuids(ctx, auth.MatchPassParam{
//			UserUuid: user.ID,
//			Password: password,
//		})
//		if err != nil || !matched {
//			return nil, errors.New("invalid credentials")
//		}
//
//		// Generate token
//		return h.tokenService.GenerateToken(user)
//	}
//
// # Password Updates
//
// Update user passwords:
//
//	// Update password for a user
//	err := authService.UpdatePassword(ctx, auth.UpdatePassParam{
//		UserUuid:    userID,
//		NewPassword: "NewP@ssw0rd123",
//	})
//	if err != nil {
//		return err
//	}
//
//	// Update with complexity validation
//	newPassword := "NewP@ssw0rd123"
//
//	// First verify complexity
//	if err := authService.VerifyPasswordComplexity(ctx, newPassword); err != nil {
//		return err
//	}
//
//	// Then update
//	err = authService.UpdatePassword(ctx, auth.UpdatePassParam{
//		UserUuid:    userID,
//		NewPassword: newPassword,
//	})
//
// # Repository Pattern
//
// The package uses repository interface for database abstraction:
//
//	type AuthRepository interface {
//		FindUserUuidsByEmail(ctx context.Context, email string) ([]uuid.UUID, error)
//	}
//
// # Custom Backend Implementation
//
// Implement repository interface for alternative storage:
//
//	type RedisAuthRepository struct {
//		client *redis.Client
//	}
//
//	func (r *RedisAuthRepository) FindUserUuidsByEmail(ctx context.Context, email string) ([]uuid.UUID, error) {
//		// Redis implementation
//		key := fmt.Sprintf("user:email:%s", email)
//		val, err := r.client.Get(ctx, key).Result()
//		if err != nil {
//			return nil, err
//		}
//		// Parse and return UUIDs
//	}
//
//	// Use with auth service
//	repo := &RedisAuthRepository{client: redisClient}
//	service := auth.NewAuthLoginService(repo, loginService)
//
// # Data Models
//
// Key types used by the package:
//
//	// PasswordComplexity defines password requirements
//	type PasswordComplexity struct {
//		RequiredDigit           bool // Require at least one digit
//		RequiredLowercase       bool // Require at least one lowercase letter
//		RequiredUppercase       bool // Require at least one uppercase letter
//		RequiredNonAlphanumeric bool // Require at least one special character
//		RequiredLength          int  // Minimum password length
//	}
//
//	// MatchPassParam for password verification
//	type MatchPassParam struct {
//		UserUuid uuid.UUID
//		Password string
//	}
//
//	// UpdatePassParam for password updates
//	type UpdatePassParam struct {
//		UserUuid    uuid.UUID
//		NewPassword string
//	}
//
// # Integration with Other Services
//
// Auth service is typically used with IAM and Login services:
//
//	// During user registration
//	func RegisterUser(ctx context.Context, email, password, name string) error {
//		// Verify password complexity
//		if err := authService.VerifyPasswordComplexity(ctx, password); err != nil {
//			return fmt.Errorf("weak password: %w", err)
//		}
//
//		// Create user
//		user, err := iamService.CreateUser(ctx, email, email, name, defaultRoles, "")
//		if err != nil {
//			return err
//		}
//
//		// Create login credentials
//		login, err := loginService.CreateLogin(ctx, email, password)
//		if err != nil {
//			return err
//		}
//
//		// Link user to login
//		_, err = iamService.UpdateUser(ctx, user.User.ID, name, defaultRoles, &login.ID)
//		return err
//	}
//
//	// During password reset
//	func ResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
//		// Verify complexity
//		if err := authService.VerifyPasswordComplexity(ctx, newPassword); err != nil {
//			return err
//		}
//
//		// Update password
//		return authService.UpdatePassword(ctx, auth.UpdatePassParam{
//			UserUuid:    userID,
//			NewPassword: newPassword,
//		})
//	}
//
// # Error Handling
//
// The package returns descriptive errors for password validation:
//
//	err := authService.VerifyPasswordComplexity(ctx, "weak")
//	if err != nil {
//		// Returns specific error messages:
//		// - "password must have at least one digit"
//		// - "password must have at least one lowercase"
//		// - "password must have at least one uppercase"
//		// - "password must have at least one non-alphanumeric character"
//		// - "password must be at least X characters"
//		fmt.Println(err.Error())
//		return err
//	}
//
// # Testing
//
// Use mock repository for testing:
//
//	type MockAuthRepository struct {
//		users map[string][]uuid.UUID
//	}
//
//	func (m *MockAuthRepository) FindUserUuidsByEmail(ctx context.Context, email string) ([]uuid.UUID, error) {
//		if uuids, ok := m.users[email]; ok {
//			return uuids, nil
//		}
//		return nil, errors.New("user not found")
//	}
//
//	// Use in tests
//	mockRepo := &MockAuthRepository{
//		users: map[string][]uuid.UUID{
//			"test@example.com": {testUserID},
//		},
//	}
//	service := auth.NewAuthLoginService(mockRepo, mockLoginService)
//
//	// Test password complexity
//	func TestPasswordComplexity(t *testing.T) {
//		service := auth.NewAuthLoginService(
//			mockRepo,
//			mockLoginService,
//			auth.WithPwdComplex(auth.PasswordComplexity{
//				RequiredLength:    8,
//				RequiredDigit:     true,
//				RequiredLowercase: true,
//				RequiredUppercase: true,
//			}),
//		)
//
//		// Should pass
//		err := service.VerifyPasswordComplexity(ctx, "MyPass123")
//		assert.NoError(t, err)
//
//		// Should fail - no digit
//		err = service.VerifyPasswordComplexity(ctx, "MyPassword")
//		assert.Error(t, err)
//	}
//
// # Best Practices
//
// 1. Password Complexity
//   - Always validate password complexity before creating/updating passwords
//   - Configure complexity requirements based on security needs
//   - Provide clear error messages to users
//
// 2. Password Matching
//   - Always use constant-time comparison (handled by login service)
//   - Don't expose whether password or username was wrong
//   - Rate-limit authentication attempts
//
// 3. Password Updates
//   - Require current password before allowing updates
//   - Validate new password complexity
//   - Invalidate existing sessions after password change
//
// 4. Error Messages
//   - Be specific in validation errors (helps users)
//   - Be generic in authentication errors (security)
//   - Log failed authentication attempts
//
// # Common Patterns
//
// Pattern 1: Registration with password validation
//
//	func Register(email, password string) error {
//		// Validate password first
//		if err := authService.VerifyPasswordComplexity(ctx, password); err != nil {
//			return fmt.Errorf("invalid password: %w", err)
//		}
//
//		// Create user and credentials
//		// ...
//	}
//
// Pattern 2: Login with password verification
//
//	func Login(email, password string) (*Token, error) {
//		user, err := getUserByEmail(email)
//		if err != nil {
//			return nil, errors.New("invalid credentials")
//		}
//
//		matched, err := authService.MatchPasswordByUuids(ctx, auth.MatchPassParam{
//			UserUuid: user.ID,
//			Password: password,
//		})
//		if err != nil || !matched {
//			return nil, errors.New("invalid credentials")
//		}
//
//		return generateToken(user)
//	}
//
// Pattern 3: Password change with validation
//
//	func ChangePassword(userID uuid.UUID, currentPassword, newPassword string) error {
//		// Verify current password
//		matched, err := authService.MatchPasswordByUuids(ctx, auth.MatchPassParam{
//			UserUuid: userID,
//			Password: currentPassword,
//		})
//		if err != nil || !matched {
//			return errors.New("current password is incorrect")
//		}
//
//		// Validate new password
//		if err := authService.VerifyPasswordComplexity(ctx, newPassword); err != nil {
//			return err
//		}
//
//		// Update password
//		return authService.UpdatePassword(ctx, auth.UpdatePassParam{
//			UserUuid:    userID,
//			NewPassword: newPassword,
//		})
//	}
//
// # Related Packages
//
//   - pkg/login - Login credential management
//   - pkg/iam - User and role management
//   - pkg/signup - User registration
//   - pkg/twofa - Two-factor authentication
//   - pkg/tokengenerator - JWT token generation
package auth
