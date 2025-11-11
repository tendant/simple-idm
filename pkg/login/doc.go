// Package login provides password-based authentication and credential management.
//
// This package handles login credentials, password hashing (bcrypt/argon2), password reset flows,
// magic link authentication, and email notifications for authentication events.
//
// # Overview
//
// The login package provides:
//   - Password-based authentication
//   - Multiple password hashing algorithms (bcrypt, argon2)
//   - Password reset with token generation
//   - Magic link (passwordless) authentication
//   - Login attempt tracking and account lockout
//   - Email notifications for authentication events
//   - Repository pattern for database abstraction
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/login"
//
//	// Create service with configuration
//	service := login.NewLoginService(login.LoginServiceConfig{
//		Queries:                queries,
//		MaxLoginAttempts:       5,
//		LockoutDuration:        15 * time.Minute,
//		PasswordHashAlgorithm:  "argon2",
//		MagicLinkExpiration:    15 * time.Minute,
//		PasswordResetExpiry:    time.Hour,
//	})
//
//	// Login with password
//	result, err := service.LoginByEmail(ctx, "user@example.com", "password123")
//	if err != nil {
//		// Handle login failure
//	}
//
// # Password Authentication
//
//	// Login by email
//	result, err := service.LoginByEmail(ctx, email, password)
//	if err != nil {
//		// Invalid credentials or account locked
//	}
//	fmt.Printf("Logged in: %s\n", result.Login.Username)
//
//	// Login by username
//	result, err := service.Login(ctx, username, password)
//
//	// Check password for specific login
//	matched, err := service.CheckPasswordByLoginId(ctx, loginID, password, hashedPassword)
//
// # Password Reset Flow
//
//	// Step 1: Initiate password reset
//	err := service.InitPasswordResetByEmail(ctx, email)
//	// Generates token and sends email
//
//	// Step 2: User receives email with reset link
//	// Frontend: https://app.com/reset-password?token=<token>
//
//	// Step 3: Reset password with token
//	err = service.ResetPassword(ctx, token, newPassword)
//	if err != nil {
//		// Token expired or invalid
//	}
//
// # Magic Link Authentication
//
//	// Generate magic link token
//	token, loginID, err := service.GenerateMagicLinkTokenByEmail(ctx, email)
//
//	// Send magic link email
//	err = service.SendMagicLinkEmail(ctx, login.SendMagicLinkEmailParams{
//		Email:     email,
//		Token:     token,
//		LoginID:   loginID,
//		MagicLink: fmt.Sprintf("https://app.com/auth/magic?token=%s", token),
//	})
//
//	// Validate magic link token
//	result, err := service.ValidateMagicLinkToken(ctx, token)
//	if err != nil {
//		// Token expired or invalid
//	}
//
// # Password Hashing
//
//	// Service supports bcrypt and argon2
//	config := login.LoginServiceConfig{
//		PasswordHashAlgorithm: "argon2", // or "bcrypt"
//	}
//
//	// Hashing is handled automatically during:
//	// - User registration
//	// - Password updates
//	// - Password resets
//
// # Account Lockout
//
//	// Configure lockout policy
//	config := login.LoginServiceConfig{
//		MaxLoginAttempts: 5,
//		LockoutDuration:  15 * time.Minute,
//	}
//
//	// Failed login attempts are tracked automatically
//	// Account locks after max attempts
//	result, err := service.LoginByEmail(ctx, email, wrongPassword)
//	// After 5 attempts: "account locked, try again in 15 minutes"
//
// # Email Notifications
//
//	// Send password reset email
//	err := service.SendPasswordResetEmail(ctx, login.SendPasswordResetEmailParams{
//		Email:     user.Email,
//		Token:     resetToken,
//		ResetLink: fmt.Sprintf("https://app.com/reset?token=%s", resetToken),
//	})
//
//	// Send username reminder
//	err := service.SendUsernameEmail(ctx, email, username)
//
//	// Send password reset notification (after successful reset)
//	err := service.SendPasswordResetNotice(ctx, login.SendPasswordResetNoticeParams{
//		Email:    email,
//		Username: username,
//	})
//
// # Repository Pattern
//
//	type LoginRepository interface {
//		CreateLogin(ctx context.Context, params CreateLoginParams) (Login, error)
//		FindLoginByUsername(ctx context.Context, username string) (Login, error)
//		FindLoginByEmail(ctx context.Context, email string) (Login, error)
//		UpdatePassword(ctx context.Context, params UpdatePasswordParams) error
//		// ... more methods
//	}
//
// # Configuration
//
//	type LoginServiceConfig struct {
//		Queries                LoginRepository
//		MaxLoginAttempts       int           // Default: 5
//		LockoutDuration        time.Duration // Default: 15m
//		PasswordHashAlgorithm  string        // "bcrypt" or "argon2"
//		MagicLinkExpiration    time.Duration // Default: 15m
//		PasswordResetExpiry    time.Duration // Default: 1h
//		NotificationService    NotificationService
//		FrontendURL            string
//	}
//
// # Common Patterns
//
// Pattern 1: Complete registration flow
//
//	func RegisterUser(email, password, username string) error {
//		// Validate password
//		if err := authService.VerifyPasswordComplexity(ctx, password); err != nil {
//			return err
//		}
//
//		// Create user
//		user, err := iamService.CreateUser(ctx, email, username, "", roles, "")
//		if err != nil {
//			return err
//		}
//
//		// Create login
//		login, err := loginService.CreateLogin(ctx, username, email, password)
//		if err != nil {
//			iamService.DeleteUser(ctx, user.User.ID)
//			return err
//		}
//
//		// Link user to login
//		_, err = iamService.UpdateUser(ctx, user.User.ID, "", roles, &login.ID)
//		return err
//	}
//
// Pattern 2: Password reset flow
//
//	func InitiatePasswordReset(email string) error {
//		return loginService.InitPasswordResetByEmail(ctx, email)
//		// Generates token and sends email automatically
//	}
//
//	func CompletePasswordReset(token, newPassword string) error {
//		// Validate password
//		if err := authService.VerifyPasswordComplexity(ctx, newPassword); err != nil {
//			return err
//		}
//
//		// Reset password
//		return loginService.ResetPassword(ctx, token, newPassword)
//	}
//
// Pattern 3: Magic link authentication
//
//	func SendMagicLink(email string) error {
//		token, loginID, err := loginService.GenerateMagicLinkTokenByEmail(ctx, email)
//		if err != nil {
//			return err
//		}
//
//		magicLink := fmt.Sprintf("%s/auth/magic?token=%s", frontendURL, token)
//		return loginService.SendMagicLinkEmail(ctx, login.SendMagicLinkEmailParams{
//			Email:     email,
//			Token:     token,
//			LoginID:   loginID,
//			MagicLink: magicLink,
//		})
//	}
//
// # Best Practices
//
//  1. Use argon2 for password hashing (more secure than bcrypt)
//  2. Configure appropriate lockout policy to prevent brute force
//  3. Set reasonable token expiration times (15m for magic links, 1h for password reset)
//  4. Always validate password complexity before accepting passwords
//  5. Send notification emails for security events (password reset, etc.)
//
// # Related Packages
//
//   - pkg/auth - Password complexity validation
//   - pkg/iam - User management
//   - pkg/signup - User registration
//   - pkg/twofa - Two-factor authentication
//   - pkg/notification - Email/SMS notifications
package login
