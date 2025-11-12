// Package logins provides login credential management and session tracking.
//
// This package manages login accounts, credentials, password policies, and login
// session tracking with support for password and passwordless authentication.
//
// # Overview
//
// The logins package provides:
//   - Login account CRUD operations
//   - Password and passwordless login creation
//   - Login search and listing
//   - Password management integration
//   - Repository pattern for database abstraction
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/logins"
//
//	// Create service
//	repo := logins.NewPostgresLoginsRepository(queries)
//	service := logins.NewLoginsService(repo).
//		WithPasswordManager(passwordManager)
//
//	// Create login with password
//	login, err := service.CreateLogin(ctx, logins.LoginCreateRequest{
//		Username: "johndoe",
//		Email:    "john@example.com",
//		Password: "SecurePass123!",
//	}, createdBy)
//
//	// Create passwordless login
//	login, err := service.CreateLoginWithoutPassword(ctx, "john@example.com", createdBy)
//
// # Login Management
//
//	// Get login by ID
//	login, err := service.GetLogin(ctx, loginID)
//
//	// Get login by username
//	login, err := service.GetLoginByUsername(ctx, "johndoe")
//
//	// List all logins with pagination
//	logins, total, err := service.ListLogins(ctx, 20, 0) // limit, offset
//
//	// Search logins
//	logins, err := service.SearchLogins(ctx, "john", 20, 0)
//
//	// Update login
//	updated, err := service.UpdateLogin(ctx, loginID, logins.LoginUpdateRequest{
//		Username: "newusername",
//		Email:    "newemail@example.com",
//	})
//
//	// Delete login
//	err = service.DeleteLogin(ctx, loginID)
//
// # Related Packages
//
//   - pkg/login - Password-based authentication
//   - pkg/loginflow - Login flow orchestration
//   - pkg/mapper - User-login mapping
package logins
