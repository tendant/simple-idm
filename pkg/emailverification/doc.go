// Package emailverification provides email verification services for simple-idm.
//
// This package manages email verification tokens, verification flow,
// and integrates with notification services to send verification emails.
//
// # Overview
//
// The emailverification package provides:
//   - Email verification token generation
//   - Token-based email verification
//   - Resend verification emails
//   - Verification status checking
//   - Token expiration and cleanup
//   - Repository pattern for PostgreSQL and file storage
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/emailverification"
//
//	// Create service
//	repo := emailverification.NewPostgresEmailVerificationRepository(queries)
//	service := emailverification.NewEmailVerificationService(
//		repo,
//		emailverification.WithNotificationService(notificationService),
//		emailverification.WithTokenExpiry(24*time.Hour),
//		emailverification.WithFrontendURL("https://app.example.com"),
//	)
//
//	// Create verification token
//	token, err := service.CreateVerificationToken(ctx, userID, userName, userEmail)
//
//	// Verify email with token
//	err = service.VerifyEmail(ctx, token)
//
// # Email Verification Flow
//
//	// Step 1: Create verification token during registration
//	token, err := service.CreateVerificationToken(ctx, user.ID, user.Name, user.Email)
//	if err != nil {
//		return err
//	}
//
//	// Token is automatically sent via email
//	// Email contains link: https://app.com/verify-email?token=<token>
//
//	// Step 2: User clicks link, frontend calls verify endpoint
//	err = service.VerifyEmail(ctx, token)
//	if err != nil {
//		// Token expired, invalid, or already used
//		return err
//	}
//
//	// Email is now verified
//
// # Resending Verification Emails
//
//	// User didn't receive email or token expired
//	err := service.ResendVerificationEmail(ctx, userID, userName, userEmail)
//	if err != nil {
//		return err
//	}
//
//	// New token generated and sent
//
// # Checking Verification Status
//
//	// Check if user's email is verified
//	verified, verifiedAt, err := service.GetVerificationStatus(ctx, userID)
//	if err != nil {
//		return err
//	}
//
//	if !verified {
//		// Prompt user to verify email
//		return errors.New("please verify your email address")
//	}
//
//	fmt.Printf("Email verified at: %v\n", verifiedAt)
//
// # Token Cleanup
//
//	// Periodically clean up expired tokens
//	err := service.CleanupExpiredTokens(ctx)
//
//	// Run as cron job
//	go func() {
//		ticker := time.NewTicker(24 * time.Hour)
//		for range ticker.C {
//			service.CleanupExpiredTokens(context.Background())
//		}
//	}()
//
// # Configuration
//
//	service := emailverification.NewEmailVerificationService(
//		repo,
//		emailverification.WithNotificationService(notificationSvc),
//		emailverification.WithTokenExpiry(24*time.Hour), // Default: 24 hours
//		emailverification.WithFrontendURL("https://app.com"),
//	)
//
// # Repository Pattern
//
//	// PostgreSQL repository
//	postgresRepo := emailverification.NewPostgresEmailVerificationRepository(queries)
//
//	// File-based repository (for testing)
//	fileRepo := emailverification.NewFileEmailVerificationRepository("./data/verifications.json")
//
//	// Use any repository implementation
//	service := emailverification.NewEmailVerificationService(repo)
//
// # Common Patterns
//
// Pattern 1: Registration with email verification
//
//	func RegisterUser(email, password, name string) error {
//		// Create user
//		user, err := iamService.CreateUser(ctx, email, email, name, roles, "")
//		if err != nil {
//			return err
//		}
//
//		// Create login
//		login, err := loginService.CreateLogin(ctx, email, password)
//		if err != nil {
//			return err
//		}
//
//		// Link user to login
//		_, err = iamService.UpdateUser(ctx, user.User.ID, name, roles, &login.ID)
//		if err != nil {
//			return err
//		}
//
//		// Send verification email
//		token, err := emailVerificationService.CreateVerificationToken(ctx, user.User.ID, name, email)
//		if err != nil {
//			log.Printf("Failed to create verification token: %v", err)
//			// Continue - user is registered but verification failed
//		}
//
//		return nil
//	}
//
// Pattern 2: Require email verification before login
//
//	func Login(email, password string) (*Token, error) {
//		// Authenticate
//		loginResult, err := loginService.LoginByEmail(ctx, email, password)
//		if err != nil {
//			return nil, err
//		}
//
//		// Check email verification
//		verified, _, err := emailVerificationService.GetVerificationStatus(ctx, loginResult.User.ID)
//		if err != nil {
//			return nil, err
//		}
//
//		if !verified {
//			return nil, errors.New("please verify your email before logging in")
//		}
//
//		// Generate token
//		return generateToken(loginResult.User)
//	}
//
// Pattern 3: Resend with rate limiting
//
//	func ResendVerificationEmail(userID uuid.UUID) error {
//		// Check last sent time to prevent spam
//		verified, lastSent, err := emailVerificationService.GetVerificationStatus(ctx, userID)
//		if err != nil {
//			return err
//		}
//
//		if verified {
//			return errors.New("email already verified")
//		}
//
//		if lastSent != nil && time.Since(*lastSent) < 5*time.Minute {
//			return errors.New("please wait before requesting another verification email")
//		}
//
//		// Get user info
//		user, err := iamService.GetUser(ctx, userID)
//		if err != nil {
//			return err
//		}
//
//		// Resend
//		return emailVerificationService.ResendVerificationEmail(ctx, userID, user.User.Name, user.User.Email)
//	}
//
// # Best Practices
//
//  1. Set reasonable token expiration (24 hours is common)
//  2. Clean up expired tokens regularly
//  3. Allow users to resend verification emails
//  4. Provide clear error messages for expired/invalid tokens
//  5. Optionally require verification before allowing login
//
// # Related Packages
//
//   - pkg/signup - User registration with email verification
//   - pkg/notification - Email delivery
//   - pkg/iam - User management
package emailverification
