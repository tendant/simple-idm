// Package mapper provides user-login mapping for simple-idm.
//
// This package handles the relationship between user accounts and login credentials,
// supporting multiple users per login and enterprise use cases.
//
// # Overview
//
// The mapper package provides:
//   - User-to-login mapping
//   - Multiple users per login support
//   - User lookup by login ID
//   - Token claims generation
//   - User switching
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/mapper"
//
//	// Get users for a login
//	users, err := userMapper.GetUsersByLoginId(ctx, loginID)
//
//	// Get specific user
//	user, err := userMapper.GetUserById(ctx, userID)
//
//	// Generate token claims
//	rootMods, extraClaims := userMapper.ToTokenClaims(user)
//
// # Multiple Users Per Login
//
// Supports enterprise scenarios where one login has multiple user accounts:
//
//	// During login
//	users, err := userMapper.GetUsersByLoginId(ctx, loginID)
//	if len(users) > 1 {
//		// Show user selection screen
//		return requireUserSelection(users)
//	}
//
//	// Single user, proceed
//	return generateTokens(users[0])
//
// # Related Packages
//
//   - pkg/iam - User management
//   - pkg/login - Login credentials
//   - pkg/loginflow - Login flow with user selection
package mapper
