// Package device provides device fingerprinting and recognition for simple-idm.
//
// This package enables device-based authentication decisions, allowing trusted
// devices to skip 2FA and tracking device usage patterns.
//
// # Overview
//
// The device package provides:
//   - Device fingerprinting (browser/device identification)
//   - Device linking to login accounts
//   - Device recognition (trusted device checking)
//   - Device expiration and cleanup
//   - "Remember this device" functionality
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/device"
//
//	// Create service
//	repo := device.NewPostgresDeviceRepository(queries)
//	service := device.NewDeviceService(
//		repo,
//		device.WithDeviceExpiration(90*24*time.Hour), // 90 days
//	)
//
//	// Check if device is recognized
//	recognized := service.IsDeviceRecognized(ctx, loginID, fingerprintStr)
//	if recognized {
//		// Skip 2FA
//	}
//
//	// Link device to login after successful 2FA
//	err := service.LinkDeviceToLogin(ctx, device.LinkDeviceParams{
//		LoginID:           loginID,
//		FingerprintString: fingerprintStr,
//		IPAddress:         clientIP,
//		UserAgent:         userAgent,
//	})
//
// # Device Recognition Flow
//
//	// During login
//	func ProcessLogin(username, password, fingerprintStr string) {
//		// Authenticate credentials
//		loginResult, err := loginService.Login(ctx, username, password)
//
//		// Check device recognition
//		recognized := deviceService.IsDeviceRecognized(ctx, loginResult.Login.ID, fingerprintStr)
//
//		if recognized {
//			// Device is trusted, skip 2FA
//			return generateTokens(loginResult.User)
//		}
//
//		// Device not recognized, require 2FA
//		return require2FA(loginResult.Login.ID)
//	}
//
// # Device Linking
//
//	// After successful 2FA with "remember device" option
//	func Complete2FA(loginID uuid.UUID, code, fingerprintStr string, remember bool) {
//		// Validate 2FA code
//		valid, err := twofaService.Validate2faPasscode(ctx, loginID, "totp", code)
//		if !valid {
//			return errors.New("invalid code")
//		}
//
//		// Link device if requested
//		if remember {
//			err = deviceService.LinkDeviceToLogin(ctx, device.LinkDeviceParams{
//				LoginID:           loginID,
//				FingerprintString: fingerprintStr,
//				IPAddress:         clientIP,
//				UserAgent:         userAgent,
//			})
//		}
//
//		return generateTokens(user)
//	}
//
// # Device Management
//
//	// List devices for a login
//	devices, err := service.GetDevicesForLogin(ctx, loginID)
//	for _, dev := range devices {
//		fmt.Printf("Device: %s, Last used: %v\n", dev.UserAgent, dev.LastLoginAt)
//	}
//
//	// Remove device
//	err = service.RemoveDevice(ctx, deviceID)
//
//	// Clean up expired devices
//	err = service.CleanupExpiredDevices(ctx)
//
// # Related Packages
//
//   - pkg/loginflow - Login flow with device recognition
//   - pkg/twofa - Two-factor authentication
package device
