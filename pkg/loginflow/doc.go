// Package loginflow provides orchestrated login flow management for simple-idm.
//
// This package coordinates multiple authentication steps including credential validation,
// 2FA, device recognition, user selection, and token generation into a cohesive flow.
//
// # Overview
//
// The loginflow package provides:
//   - Complete login flow orchestration
//   - Multi-step authentication (credentials → 2FA → tokens)
//   - Device recognition (skip 2FA on trusted devices)
//   - Multiple user selection per login
//   - Magic link authentication
//   - Token refresh flows
//   - User switching
//   - Mobile and web flow variants
//
// # Architecture
//
// LoginFlowService coordinates multiple services:
//   - login.LoginService - Credential validation
//   - twofa.TwoFactorService - 2FA validation
//   - device.DeviceService - Device recognition
//   - tokengenerator.TokenService - JWT generation
//   - mapper.UserMapper - User lookups
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/loginflow"
//
//	// Create service
//	flowService := loginflow.NewLoginFlowService(
//		loginService,
//		twoFactorService,
//		deviceService,
//		tokenService,
//		tokenCookieService,
//		userMapper,
//	)
//
//	// Process login
//	result := flowService.ProcessLogin(ctx, loginflow.Request{
//		Username:          "user@example.com",
//		Password:          "password123",
//		IPAddress:         "192.168.1.1",
//		UserAgent:         "Mozilla/5.0...",
//		DeviceFingerprint: fingerprintData,
//	})
//
// # Login Flow Steps
//
// Standard login flow progresses through these steps:
//
//  1. **Credential Authentication** - Validate username/password
//  2. **User Validation** - Check account status (not locked/disabled)
//  3. **Device Recognition** - Check if device is recognized
//  4. **2FA Requirement** - Determine if 2FA is needed
//  5. **2FA Validation** - Validate 2FA code (if required)
//  6. **User Selection** - Handle multiple users per login (if applicable)
//  7. **Token Generation** - Generate access and refresh tokens
//  8. **Device Remembering** - Link device to login (if requested)
//
// # Complete Login Flow
//
// Step 1: Initial Login Request
//
//	result := flowService.ProcessLogin(ctx, loginflow.Request{
//		Username:             "user@example.com",
//		Password:             "password123",
//		IPAddress:            clientIP,
//		UserAgent:            userAgent,
//		DeviceFingerprintStr: deviceFingerprint,
//	})
//
//	if !result.Success {
//		// Handle error
//		return result.ErrorResponse
//	}
//
// Step 2: Handle 2FA Requirement
//
//	if result.RequiresTwoFA {
//		// Display 2FA form with available methods
//		for _, method := range result.TwoFactorMethods {
//			fmt.Printf("2FA Method: %s\n", method.Type)
//			for _, option := range method.DeliveryOptions {
//				fmt.Printf("  Option: %s (%s)\n", option.Type, option.DisplayValue)
//			}
//		}
//
//		// User enters 2FA code
//		twoFAResult := flowService.Process2FAValidation(ctx, loginflow.TwoFAValidationRequest{
//			TempToken:      result.Tokens["temp_token"].Value,
//			TwoFACode:      userEnteredCode,
//			TwoFAType:      selectedMethod,
//			RememberDevice: true, // Skip 2FA on this device in future
//		})
//
//		if twoFAResult.Success {
//			// Login complete, use twoFAResult.Tokens
//		}
//	}
//
// Step 3: Handle Multiple Users
//
//	if result.RequiresUserSelection {
//		// Display user selection
//		for _, user := range result.Users {
//			fmt.Printf("User: %s (%s)\n", user.Name, user.Email)
//		}
//
//		// User selects account
//		switchResult := flowService.ProcessUserSwitch(ctx, loginflow.UserSwitchRequest{
//			TempToken: result.Tokens["temp_token"].Value,
//			UserID:    selectedUserID,
//		})
//
//		if switchResult.Success {
//			// Login complete, use switchResult.Tokens
//		}
//	}
//
// Step 4: Success
//
//	if result.Success {
//		// Use tokens
//		accessToken := result.Tokens["access_token"].Value
//		refreshToken := result.Tokens["refresh_token"].Value
//
//		// Set cookies and redirect
//		setTokenCookies(w, accessToken, refreshToken)
//		http.Redirect(w, r, "/dashboard", http.StatusFound)
//	}
//
// # Flow Variants
//
// Web Login Flow:
//
//	result := flowService.ProcessLogin(ctx, request)
//
// Mobile Login Flow:
//
//	result := flowService.ProcessMobileLogin(ctx, request)
//
// Email Login Flow:
//
//	result := flowService.ProcessLoginByEmail(ctx, email, password, ip, userAgent, fingerprint)
//
// Magic Link Flow:
//
//	result := flowService.ProcessMagicLinkValidation(ctx, token, ip, userAgent, fingerprint)
//
// # 2FA Flows
//
// Send 2FA Code:
//
//	result := flowService.Process2FASend(ctx, loginflow.TwoFASendRequest{
//		TempToken:      tempToken,
//		TwoFAType:      "sms",
//		DeliveryOption: "+1-555-0123",
//	})
//
// Validate 2FA Code:
//
//	result := flowService.Process2FAValidation(ctx, loginflow.TwoFAValidationRequest{
//		TempToken:      tempToken,
//		TwoFACode:      "123456",
//		TwoFAType:      "totp",
//		RememberDevice: true,
//	})
//
// # Device Recognition
//
// Device recognition allows skipping 2FA on trusted devices:
//
//	// Automatic during login
//	result := flowService.ProcessLogin(ctx, loginflow.Request{
//		Username:             username,
//		Password:             password,
//		DeviceFingerprintStr: fingerprint,
//	})
//
//	if result.DeviceRecognized {
//		// Device was recognized, 2FA skipped
//	}
//
//	// Remember device after 2FA
//	result := flowService.Process2FAValidation(ctx, loginflow.TwoFAValidationRequest{
//		TempToken:      tempToken,
//		TwoFACode:      code,
//		RememberDevice: true, // Link device to login
//	})
//
// # Token Refresh
//
// Web Token Refresh:
//
//	result := flowService.ProcessTokenRefresh(ctx, loginflow.TokenRefreshRequest{
//		RefreshToken: refreshToken,
//	})
//
//	if result.Success {
//		newAccessToken := result.Tokens["access_token"].Value
//	}
//
// Mobile Token Refresh:
//
//	result := flowService.ProcessMobileTokenRefresh(ctx, loginflow.TokenRefreshRequest{
//		RefreshToken: refreshToken,
//	})
//
// # User Switching
//
// For logins with multiple associated users:
//
//	// Get available users
//	result := flowService.ProcessLogin(ctx, request)
//	if result.RequiresUserSelection {
//		// Display users: result.Users
//
//		// Switch to selected user
//		switchResult := flowService.ProcessUserSwitch(ctx, loginflow.UserSwitchRequest{
//			TempToken: result.Tokens["temp_token"].Value,
//			UserID:    selectedUserID,
//		})
//	}
//
// # Error Handling
//
//	result := flowService.ProcessLogin(ctx, request)
//	if !result.Success {
//		switch result.ErrorResponse.Type {
//		case loginflow.ErrorTypeAccountLocked:
//			// Account is locked
//		case loginflow.ErrorTypePasswordExpired:
//			// Password has expired
//		case loginflow.ErrorTypeInvalidCredentials:
//			// Wrong username or password
//		case loginflow.ErrorTypeNoUserFound:
//			// User doesn't exist
//		case loginflow.ErrorTypeInternalError:
//			// Server error
//		}
//	}
//
// # Result Fields
//
//	type Result struct {
//		Success                 bool              // Login completed successfully
//		RequiresTwoFA           bool              // 2FA required
//		RequiresUserSelection   bool              // Multiple users available
//		RequiresUserAssociation bool              // User association needed
//		Users                   []mapper.User     // Available users
//		LoginID                 uuid.UUID         // Login ID
//		TwoFactorMethods        []TwoFactorMethod // Available 2FA methods
//		Tokens                  map[string]TokenValue // Generated tokens
//		DeviceRecognized        bool              // Device was recognized
//		ErrorResponse           *Error            // Error details
//	}
//
// # Common Patterns
//
// Pattern 1: Simple login (no 2FA, single user)
//
//	func HandleLogin(w http.ResponseWriter, r *http.Request) {
//		result := flowService.ProcessLogin(ctx, loginflow.Request{
//			Username:             r.FormValue("username"),
//			Password:             r.FormValue("password"),
//			IPAddress:            getClientIP(r),
//			UserAgent:            r.UserAgent(),
//			DeviceFingerprintStr: r.FormValue("device_fingerprint"),
//		})
//
//		if !result.Success {
//			http.Error(w, result.ErrorResponse.Message, http.StatusUnauthorized)
//			return
//		}
//
//		setTokenCookies(w, result.Tokens)
//		http.Redirect(w, r, "/dashboard", http.StatusFound)
//	}
//
// Pattern 2: Multi-step flow with 2FA
//
//	func HandleLogin(w http.ResponseWriter, r *http.Request) {
//		result := flowService.ProcessLogin(ctx, request)
//
//		if result.RequiresTwoFA {
//			// Store temp token in session
//			session.Set("temp_token", result.Tokens["temp_token"].Value)
//
//			// Redirect to 2FA page
//			respondJSON(w, map[string]interface{}{
//				"require_2fa": true,
//				"methods":     result.TwoFactorMethods,
//			})
//			return
//		}
//
//		// Complete login
//		setTokenCookies(w, result.Tokens)
//		respondJSON(w, map[string]interface{}{"success": true})
//	}
//
//	func Handle2FAValidation(w http.ResponseWriter, r *http.Request) {
//		tempToken := session.Get("temp_token")
//
//		result := flowService.Process2FAValidation(ctx, loginflow.TwoFAValidationRequest{
//			TempToken:      tempToken,
//			TwoFACode:      r.FormValue("code"),
//			TwoFAType:      r.FormValue("type"),
//			RememberDevice: r.FormValue("remember") == "true",
//		})
//
//		if !result.Success {
//			http.Error(w, "invalid code", http.StatusUnauthorized)
//			return
//		}
//
//		setTokenCookies(w, result.Tokens)
//		respondJSON(w, map[string]interface{}{"success": true})
//	}
//
// Pattern 3: Magic link authentication
//
//	func HandleMagicLink(w http.ResponseWriter, r *http.Request) {
//		token := r.URL.Query().Get("token")
//
//		result := flowService.ProcessMagicLinkValidation(ctx, token, getClientIP(r), r.UserAgent(), fingerprint)
//
//		if !result.Success {
//			http.Error(w, "invalid or expired link", http.StatusUnauthorized)
//			return
//		}
//
//		setTokenCookies(w, result.Tokens)
//		http.Redirect(w, r, "/dashboard", http.StatusFound)
//	}
//
// # Best Practices
//
//  1. Always collect device fingerprints for device recognition
//  2. Use temp tokens for multi-step flows (2FA, user selection)
//  3. Implement proper error handling for each error type
//  4. Allow users to remember devices to skip 2FA
//  5. Support multiple 2FA methods for flexibility
//  6. Log all authentication attempts
//
// # Related Packages
//
//   - pkg/login - Credential validation
//   - pkg/twofa - Two-factor authentication
//   - pkg/device - Device recognition
//   - pkg/tokengenerator - JWT token generation
//   - pkg/mapper - User-login mapping
package loginflow
