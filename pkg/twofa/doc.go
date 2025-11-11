// Package twofa provides two-factor authentication (2FA) services for simple-idm.
//
// This package supports multiple 2FA methods including TOTP (Time-based One-Time Password),
// SMS codes, and email codes with QR code generation for authenticator apps.
//
// # Overview
//
// The twofa package provides:
//   - TOTP (Time-based One-Time Password) authentication
//   - SMS-based 2FA with code delivery
//   - Email-based 2FA with code delivery
//   - QR code generation for authenticator apps
//   - Enable/disable 2FA per user
//   - Multiple 2FA methods per user
//   - Configurable code expiration periods
//
// # Supported 2FA Methods
//
//   - **TOTP** - Time-based codes from authenticator apps (Google Authenticator, Authy, etc.)
//   - **SMS** - Codes sent via SMS to user's phone
//   - **Email** - Codes sent via email
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/twofa"
//
//	// Create service
//	service := twofa.NewTwoFaService(
//		repo,
//		twofa.WithNotificationManager(notificationManager),
//		twofa.WithUserMapper(userMapper),
//		twofa.WithTotpPeriod(30),   // TOTP code validity: 30 seconds
//		twofa.WithSmsPeriod(300),   // SMS code validity: 5 minutes
//		twofa.WithEmailPeriod(300), // Email code validity: 5 minutes
//	)
//
//	// Enable TOTP for a user
//	err := service.EnableTwoFactor(ctx, loginID, "totp")
//
//	// Validate 2FA code
//	valid, err := service.Validate2faPasscode(ctx, loginID, "totp", "123456")
//
// # TOTP (Authenticator App) Setup
//
//	// Generate TOTP secret and QR code
//	qrCodeBase64, secret, err := service.GenerateTotpQRCode(ctx, loginID, "MyApp", "user@example.com")
//	if err != nil {
//		return err
//	}
//
//	// Display QR code to user (base64 encoded PNG)
//	// User scans with Google Authenticator, Authy, etc.
//
//	// User enters code from app to verify setup
//	valid, err := service.Validate2faPasscode(ctx, loginID, "totp", userEnteredCode)
//	if !valid {
//		return errors.New("invalid verification code")
//	}
//
//	// Enable TOTP 2FA
//	err = service.EnableTwoFactor(ctx, loginID, "totp")
//
// # SMS-Based 2FA
//
//	// Send SMS code to user
//	err := service.SendTwoFaNotification(ctx, loginID, userID, "sms", hashedPhone)
//	if err != nil {
//		return err
//	}
//
//	// User receives SMS with 6-digit code
//
//	// Validate code entered by user
//	valid, err := service.Validate2faPasscode(ctx, loginID, "sms", codeFromUser)
//	if !valid {
//		return errors.New("invalid SMS code")
//	}
//
//	// Enable SMS 2FA
//	err = service.EnableTwoFactor(ctx, loginID, "sms")
//
// # Email-Based 2FA
//
//	// Send email code to user
//	err := service.SendTwoFaNotification(ctx, loginID, userID, "email", hashedEmail)
//	if err != nil {
//		return err
//	}
//
//	// User receives email with 6-digit code
//
//	// Validate code
//	valid, err := service.Validate2faPasscode(ctx, loginID, "email", codeFromUser)
//	if !valid {
//		return errors.New("invalid email code")
//	}
//
//	// Enable email 2FA
//	err = service.EnableTwoFactor(ctx, loginID, "email")
//
// # Managing 2FA Methods
//
//	// List all 2FA methods for a user
//	methods, err := service.FindTwoFAsByLoginId(ctx, loginID)
//	for _, method := range methods {
//		fmt.Printf("Type: %s, Enabled: %v\n", method.Type, method.Enabled)
//	}
//
//	// List enabled 2FA methods
//	enabled, err := service.FindEnabledTwoFAs(ctx, loginID)
//	fmt.Printf("Enabled methods: %v\n", enabled) // ["totp", "sms"]
//
//	// Disable a 2FA method
//	err = service.DisableTwoFactor(ctx, loginID, "sms")
//
//	// Delete a 2FA method
//	err = service.DeleteTwoFactor(ctx, twofa.DeleteTwoFactorParams{
//		LoginID: loginID,
//		Type:    "email",
//	})
//
// # Login Flow with 2FA
//
//	func LoginWithTwoFactor(ctx context.Context, username, password, code2fa string) error {
//		// Step 1: Verify password
//		loginResult, err := loginService.Login(ctx, username, password)
//		if err != nil {
//			return err
//		}
//
//		// Step 2: Check if 2FA is enabled
//		enabled2FA, err := twofaService.FindEnabledTwoFAs(ctx, loginResult.Login.ID)
//		if err != nil {
//			return err
//		}
//
//		if len(enabled2FA) == 0 {
//			// No 2FA required, proceed with login
//			return generateToken(loginResult)
//		}
//
//		// Step 3: Validate 2FA code
//		// Try each enabled method
//		for _, method := range enabled2FA {
//			valid, err := twofaService.Validate2faPasscode(ctx, loginResult.Login.ID, method, code2fa)
//			if err == nil && valid {
//				// 2FA passed, proceed with login
//				return generateToken(loginResult)
//			}
//		}
//
//		return errors.New("invalid 2FA code")
//	}
//
// # Configuration Options
//
//	service := twofa.NewTwoFaService(
//		repo,
//		twofa.WithTotpPeriod(30),        // TOTP: 30 second window (default)
//		twofa.WithSmsPeriod(300),        // SMS: 5 minute validity (default)
//		twofa.WithEmailPeriod(300),      // Email: 5 minute validity (default)
//		twofa.WithNotificationManager(nm), // For sending SMS/Email
//		twofa.WithUserMapper(mapper),    // For user lookups
//	)
//
// # Common Patterns
//
// Pattern 1: TOTP setup flow
//
//	func SetupTOTP(ctx context.Context, loginID uuid.UUID, email string) (string, error) {
//		// Generate QR code
//		qrCode, secret, err := twofaService.GenerateTotpQRCode(ctx, loginID, "MyApp", email)
//		if err != nil {
//			return "", err
//		}
//
//		// Return QR code to display to user
//		// User scans with authenticator app
//		return qrCode, nil
//	}
//
//	func VerifyAndEnableTOTP(ctx context.Context, loginID uuid.UUID, code string) error {
//		// Verify user can generate correct codes
//		valid, err := twofaService.Validate2faPasscode(ctx, loginID, "totp", code)
//		if err != nil || !valid {
//			return errors.New("invalid verification code")
//		}
//
//		// Enable TOTP
//		return twofaService.EnableTwoFactor(ctx, loginID, "totp")
//	}
//
// Pattern 2: SMS 2FA during login
//
//	func RequireSMS2FA(ctx context.Context, loginID, userID uuid.UUID, phone string) error {
//		// Send SMS code
//		hashedPhone := hashDeliveryOption(phone)
//		err := twofaService.SendTwoFaNotification(ctx, loginID, userID, "sms", hashedPhone)
//		if err != nil {
//			return err
//		}
//
//		// User receives SMS
//		return nil
//	}
//
//	func ValidateSMS2FA(ctx context.Context, loginID uuid.UUID, code string) (bool, error) {
//		return twofaService.Validate2faPasscode(ctx, loginID, "sms", code)
//	}
//
// Pattern 3: Multiple 2FA methods
//
//	func Get2FAMethods(ctx context.Context, loginID uuid.UUID) ([]string, error) {
//		// Get enabled methods
//		methods, err := twofaService.FindEnabledTwoFAs(ctx, loginID)
//		if err != nil {
//			return nil, err
//		}
//
//		// Let user choose which method to use
//		return methods, nil
//	}
//
// # Best Practices
//
//  1. Always require 2FA verification during TOTP setup
//  2. Set appropriate code expiration times (5 minutes for SMS/Email)
//  3. Allow users to have backup 2FA methods
//  4. Provide recovery codes for account recovery
//  5. Send notifications when 2FA settings are changed
//
// # Security Considerations
//
//  1. TOTP is more secure than SMS/Email (not dependent on delivery)
//  2. SMS can be intercepted (SIM swapping attacks)
//  3. Store 2FA secrets encrypted in database
//  4. Rate-limit 2FA code validation attempts
//  5. Log all 2FA enable/disable actions
//
// # Related Packages
//
//   - pkg/login - Login credential management
//   - pkg/loginflow - Login flow orchestration with 2FA
//   - pkg/notification - SMS and email delivery
//   - pkg/device - Device recognition (skip 2FA on trusted devices)
package twofa
