// Package delegate provides delegation and impersonation for simple-idm.
//
// This package enables administrators and authorized users to act on behalf of
// other users with proper audit trails and permission checks.
//
// # Overview
//
// The delegate package provides:
//   - User impersonation (admin acting as user)
//   - Delegation rules and policies
//   - Permission-based delegation
//   - Audit logging
//   - Temporary delegation tokens
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/delegate"
//
//	// Create service
//	service := delegate.NewDelegateService(repo)
//
//	// Create delegation
//	delegation, err := service.CreateDelegation(ctx, delegate.CreateRequest{
//		DelegatorID: adminUserID,
//		DelegateID:  targetUserID,
//		Permissions: []string{"read", "write"},
//		ExpiresAt:   time.Now().Add(24 * time.Hour),
//	})
//
//	// Impersonate user
//	token, err := service.ImpersonateUser(ctx, adminUserID, targetUserID)
//
// # Impersonation
//
//	// Admin impersonates a user
//	func ImpersonateUser(adminID, targetUserID uuid.UUID) (*Token, error) {
//		// Check admin permissions
//		if !isAdmin(adminID) {
//			return nil, errors.New("unauthorized")
//		}
//
//		// Create impersonation token
//		token, err := delegateService.ImpersonateUser(ctx, adminID, targetUserID)
//		if err != nil {
//			return nil, err
//		}
//
//		// Token contains:
//		// - sub: targetUserID (acting as this user)
//		// - impersonator: adminID (actual user)
//		// - audit_log: true
//
//		return token, nil
//	}
//
// # Related Packages
//
//   - pkg/iam - User and role management
//   - pkg/role - Permission checking
package delegate
