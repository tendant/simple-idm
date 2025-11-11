// Package signup provides user registration services for simple-idm.
//
// This package handles user registration with password or passwordless flows,
// invitation code validation, email verification, and integration with IAM,
// login, and role services.
//
// # Overview
//
// The signup package provides:
//   - User registration with password
//   - Passwordless registration
//   - Invitation code validation
//   - Email verification integration
//   - Default role assignment
//   - Registration enable/disable toggle
//   - Service layer separated from HTTP handlers
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/signup"
//
//	// Create service with all dependencies
//	service := signup.NewSignupServiceWithOptions(
//		signup.WithIamService(iamService),
//		signup.WithRoleService(roleService),
//		signup.WithLoginService(loginService),
//		signup.WithLoginsService(loginsService),
//		signup.WithEmailVerificationService(emailVerificationService),
//		signup.WithRegistrationEnabled(true),
//		signup.WithDefaultRole("user"),
//	)
//
//	// Register user
//	result, err := service.RegisterUser(ctx, signup.RegisterUserRequest{
//		Username:       "johndoe",
//		Email:          "john@example.com",
//		Password:       "SecurePass123!",
//		Fullname:       "John Doe",
//		InvitationCode: "INVITE123",
//	})
//
// # User Registration with Password
//
//	// Register new user
//	result, err := service.RegisterUser(ctx, signup.RegisterUserRequest{
//		Username: "johndoe",
//		Email:    "john@example.com",
//		Password: "SecurePass123!",
//		Fullname: "John Doe",
//	})
//	if err != nil {
//		// Handle errors: registration disabled, username exists, weak password, etc.
//	}
//
//	fmt.Printf("User created: %s\n", result.UserID)
//	fmt.Printf("Login created: %s\n", result.LoginID)
//	fmt.Printf("Verification token: %s\n", result.VerificationToken)
//
// # Passwordless Registration
//
//	// Register without password (magic link authentication)
//	result, err := service.RegisterUserPasswordless(ctx, signup.RegisterUserPasswordlessRequest{
//		Email:          "jane@example.com",
//		Fullname:       "Jane Doe",
//		InvitationCode: "INVITE456",
//	})
//	if err != nil {
//		// Handle registration errors
//	}
//
//	// User can login via magic link sent to email
//
// # Invitation Codes
//
//	// Require invitation code for registration
//	result, err := service.RegisterUser(ctx, signup.RegisterUserRequest{
//		Username:       "user",
//		Email:          "user@example.com",
//		Password:       "password",
//		InvitationCode: "REQUIRED_CODE",
//	})
//
//	// Invitation codes are validated during registration
//	// Invalid codes will cause registration to fail
//
// # Email Verification
//
//	// Registration automatically creates verification token
//	result, err := service.RegisterUser(ctx, req)
//
//	// Send verification email (handled by email verification service)
//	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", frontendURL, result.VerificationToken)
//	emailService.SendVerificationEmail(result.Email, verificationLink)
//
// # Configuration Options
//
//	service := signup.NewSignupServiceWithOptions(
//		signup.WithRegistrationEnabled(true),        // Enable/disable registration
//		signup.WithDefaultRole("user"),               // Default role for new users
//		signup.WithIamService(iamService),            // Required
//		signup.WithRoleService(roleService),          // Required
//		signup.WithLoginService(loginService),        // Required for password registration
//		signup.WithLoginsService(loginsService),      // Required
//		signup.WithEmailVerificationService(emailSvc), // Optional
//	)
//
// # Password Policy
//
//	// Get password policy for display to users
//	policy, err := service.GetPasswordPolicy(ctx)
//	fmt.Printf("Min length: %d\n", policy.MinLength)
//	fmt.Printf("Require uppercase: %v\n", policy.RequireUppercase)
//
// # Error Handling
//
//	result, err := service.RegisterUser(ctx, req)
//	if err != nil {
//		var signupErr *signup.SignupError
//		if errors.As(err, &signupErr) {
//			switch signupErr.Code {
//			case signup.ErrCodeRegistrationDisabled:
//				// Registration is disabled
//			case signup.ErrCodeUsernameExists:
//				// Username already taken
//			case signup.ErrCodePasswordComplexity:
//				// Password too weak
//			case signup.ErrCodeInvalidInvitation:
//				// Invalid invitation code
//			}
//		}
//	}
//
// # HTTP Handler Integration
//
//	// The package provides HTTP handlers in handle.go
//	handler := signup.NewHandle(service)
//
//	// Register routes
//	r.Post("/api/idm/signup/register", handler.RegisterUser)
//	r.Post("/api/idm/signup/register-passwordless", handler.RegisterUserPasswordless)
//	r.Get("/api/idm/signup/password-policy", handler.GetPasswordPolicy)
//
// # Common Patterns
//
// Pattern 1: Complete registration flow
//
//	func CompleteRegistration(req RegisterUserRequest) error {
//		// Register user
//		result, err := signupService.RegisterUser(ctx, req)
//		if err != nil {
//			return err
//		}
//
//		// Send verification email
//		verificationLink := fmt.Sprintf("%s/verify?token=%s", frontendURL, result.VerificationToken)
//		err = emailService.SendVerificationEmail(result.Email, verificationLink)
//		if err != nil {
//			log.Printf("Failed to send verification email: %v", err)
//			// Continue - user is registered but email failed
//		}
//
//		// Send welcome email
//		err = emailService.SendWelcomeEmail(result.Email, result.Username)
//		return err
//	}
//
// Pattern 2: Conditional registration
//
//	func RegisterIfAllowed(req RegisterUserRequest) error {
//		// Check if registration is enabled
//		policy, err := signupService.GetPasswordPolicy(ctx)
//		if err != nil {
//			return err
//		}
//
//		// Register user
//		return signupService.RegisterUser(ctx, req)
//	}
//
// Pattern 3: Passwordless registration for invited users
//
//	func RegisterInvitedUser(email, invitationCode string) error {
//		result, err := signupService.RegisterUserPasswordless(ctx, signup.RegisterUserPasswordlessRequest{
//			Email:          email,
//			InvitationCode: invitationCode,
//		})
//		if err != nil {
//			return err
//		}
//
//		// Send magic link for first login
//		magicLink, err := loginService.GenerateMagicLinkTokenByEmail(ctx, email)
//		if err != nil {
//			return err
//		}
//
//		return emailService.SendMagicLinkEmail(email, magicLink)
//	}
//
// # Best Practices
//
//  1. Always validate password complexity before registration
//  2. Send email verification links immediately after registration
//  3. Use invitation codes to control who can register
//  4. Provide clear error messages for registration failures
//  5. Consider passwordless registration for better UX
//
// # Related Packages
//
//   - pkg/iam - User and role management
//   - pkg/login - Login credential management
//   - pkg/auth - Password complexity validation
//   - pkg/emailverification - Email verification
//   - pkg/role - Role management
package signup
