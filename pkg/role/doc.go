// Package role provides role-based access control (RBAC) for simple-idm.
//
// This package manages roles and user-role assignments with support for
// PostgreSQL and alternative storage backends through repository interfaces.
//
// # Overview
//
// The role package provides:
//   - Role lifecycle management (CRUD operations)
//   - User-role assignments
//   - Role-based permission checking
//   - Repository pattern for database abstraction
//
// # Basic Usage
//
//	import "github.com/tendant/simple-idm/pkg/role"
//
//	// Create service
//	repo := role.NewPostgresRoleRepository(queries)
//	service := role.NewRoleService(repo)
//
//	// Create a role
//	roleID, err := service.CreateRole(ctx, "editor")
//
//	// Assign user to role
//	err = service.AddUserToRole(ctx, roleID, userID, username)
//
// # Role Management
//
//	// List all roles
//	roles, err := service.FindRoles(ctx)
//	for _, role := range roles {
//		fmt.Printf("%s: %s\n", role.ID, role.Name)
//	}
//
//	// Get role by ID
//	role, err := service.GetRole(ctx, roleID)
//
//	// Get role by name
//	roleID, err := service.GetRoleIdByName(ctx, "admin")
//
//	// Update role
//	err = service.UpdateRole(ctx, roleID, "senior-editor")
//
//	// Delete role
//	err = service.DeleteRole(ctx, roleID)
//
// # User-Role Assignments
//
//	// Add user to role
//	err := service.AddUserToRole(ctx, roleID, userID, username)
//
//	// Get users in role
//	users, err := service.GetRoleUsers(ctx, roleID)
//	for _, user := range users {
//		fmt.Printf("User: %s (%s)\n", user.Username, user.UserID)
//	}
//
//	// Remove user from role
//	err = service.RemoveUserFromRole(ctx, roleID, userID)
//
// # Common Patterns
//
// Pattern 1: Bootstrap default roles
//
//	func BootstrapRoles(ctx context.Context, service *role.RoleService) error {
//		defaultRoles := []string{"admin", "user", "editor", "viewer"}
//
//		existing, _ := service.FindRoles(ctx)
//		existingNames := make(map[string]bool)
//		for _, r := range existing {
//			existingNames[r.Name] = true
//		}
//
//		for _, roleName := range defaultRoles {
//			if !existingNames[roleName] {
//				_, err := service.CreateRole(ctx, roleName)
//				if err != nil {
//					return err
//				}
//			}
//		}
//		return nil
//	}
//
// Pattern 2: Permission checking
//
//	func HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
//		user, err := iamService.GetUser(ctx, userID)
//		if err != nil {
//			return false, err
//		}
//
//		for _, role := range user.Roles {
//			if role.Name == roleName {
//				return true, nil
//			}
//		}
//		return false, nil
//	}
//
// Pattern 3: Assign default role during signup
//
//	func RegisterUser(email, password string) error {
//		// Get default role
//		roleID, err := roleService.GetRoleIdByName(ctx, "user")
//		if err != nil {
//			return err
//		}
//
//		// Create user with role
//		user, err := iamService.CreateUser(ctx, email, email, "", []uuid.UUID{roleID}, "")
//		if err != nil {
//			return err
//		}
//
//		// Create login credentials
//		return loginService.CreateLogin(ctx, email, password)
//	}
//
// # Related Packages
//
//   - pkg/iam - User and group management
//   - pkg/auth - Authentication
//   - pkg/signup - User registration
package role
