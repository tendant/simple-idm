// Package profile provides user profile management services for simple-idm.
//
// This package handles user profile updates including username, phone number,
// password changes, and integration with login and mapper services.
//
// # Overview
//
// The profile package provides:
//   - Username updates
//   - Phone number management
//   - Password changes with notifications
//   - Login ID management
//   - Token claims generation
//   - Multiple user-login associations
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/profile"
//
//	// Create service
//	service := profile.NewProfileService(
//		loginService,
//		mapperService,
//		notificationService,
//	)
//
//	// Update username
//	err := service.UpdateUsername(ctx, profile.UpdateUsernameParams{
//		LoginID:     loginID,
//		NewUsername: "newusername",
//	})
//
// # Username Management
//
//	// Update username
//	err := service.UpdateUsername(ctx, profile.UpdateUsernameParams{
//		LoginID:     loginID,
//		NewUsername: "john_doe_2024",
//	})
//	if err != nil {
//		// Handle error: username taken, invalid format, etc.
//	}
//
// # Phone Number Management
//
//	// Update phone number
//	err := service.UpdateUserPhone(ctx, userID, "+1-555-0123")
//	if err != nil {
//		return err
//	}
//
//	// Get user's phone number
//	phone, err := service.GetUserPhone(ctx, userID)
//	fmt.Printf("User phone: %s\n", phone)
//
// # Password Management
//
//	// Update password
//	err := service.UpdatePassword(ctx, profile.UpdatePasswordParams{
//		LoginID:     loginID,
//		OldPassword: "CurrentPass123!",
//		NewPassword: "NewSecurePass456!",
//	})
//	if err != nil {
//		// Handle error: incorrect old password, weak new password, etc.
//	}
//
//	// Password update automatically sends notification email
//
//	// Get password policy
//	policy := service.GetPasswordPolicy()
//	fmt.Printf("Min length: %d\n", policy.MinLength)
//	fmt.Printf("Require uppercase: %v\n", policy.RequireUppercase)
//
// # Login ID Management
//
//	// Update login ID for a user
//	newLoginID, err := service.UpdateLoginId(ctx, profile.UpdateLoginIdParam{
//		UserID:  userID,
//		LoginID: newLoginID,
//	})
//	if err != nil {
//		return err
//	}
//
//	// Get users associated with a login ID
//	users, err := service.GetUsersByLoginId(ctx, loginID)
//	for _, user := range users {
//		fmt.Printf("User: %s (%s)\n", user.Name, user.Email)
//	}
//
//	// Get login record
//	login, err := service.GetLoginById(ctx, loginID)
//	fmt.Printf("Username: %s, Email: %s\n", login.Username, login.Email)
//
// # Token Claims
//
//	// Generate JWT token claims for a user
//	rootMods, extraClaims := service.ToTokenClaims(user)
//
//	// rootMods contains standard claims
//	// extraClaims contains custom application claims
//
// # Password Update Notifications
//
//	// Automatically sent after password update
//	err := service.SendPasswordUpdateNotice(ctx, profile.SendPasswordUpdateNoticeParams{
//		Email:    user.Email,
//		Username: user.Username,
//	})
//
// # Common Patterns
//
// Pattern 1: Complete profile update flow
//
//	func UpdateUserProfile(ctx context.Context, userID uuid.UUID, updates ProfileUpdates) error {
//		// Update username if changed
//		if updates.Username != "" {
//			err := profileService.UpdateUsername(ctx, profile.UpdateUsernameParams{
//				LoginID:     user.LoginID,
//				NewUsername: updates.Username,
//			})
//			if err != nil {
//				return fmt.Errorf("username update failed: %w", err)
//			}
//		}
//
//		// Update phone if changed
//		if updates.Phone != "" {
//			err := profileService.UpdateUserPhone(ctx, userID, updates.Phone)
//			if err != nil {
//				return fmt.Errorf("phone update failed: %w", err)
//			}
//		}
//
//		return nil
//	}
//
// Pattern 2: Password change with validation
//
//	func ChangePassword(ctx context.Context, loginID uuid.UUID, oldPass, newPass string) error {
//		// Get password policy
//		policy := profileService.GetPasswordPolicy()
//
//		// Validate new password against policy
//		if len(newPass) < policy.MinLength {
//			return fmt.Errorf("password must be at least %d characters", policy.MinLength)
//		}
//
//		// Update password
//		err := profileService.UpdatePassword(ctx, profile.UpdatePasswordParams{
//			LoginID:     loginID,
//			OldPassword: oldPass,
//			NewPassword: newPass,
//		})
//		if err != nil {
//			return err
//		}
//
//		// Notification email sent automatically
//		return nil
//	}
//
// Pattern 3: User switching (multiple accounts)
//
//	func SwitchUserAccount(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
//		// Get all users for this login
//		users, err := profileService.GetUsersByLoginId(ctx, loginID)
//		if err != nil {
//			return nil, err
//		}
//
//		// Return available users to switch to
//		return users, nil
//	}
//
// # Best Practices
//
//  1. Always validate current password before allowing password changes
//  2. Check password policy before accepting new passwords
//  3. Send notification emails for security-sensitive changes
//  4. Validate username format and uniqueness
//  5. Support multiple users per login for enterprise use cases
//
// # Related Packages
//
//   - pkg/login - Login credential management
//   - pkg/mapper - User-login mapping
//   - pkg/notification - Email/SMS notifications
//   - pkg/auth - Password complexity validation
package profile
