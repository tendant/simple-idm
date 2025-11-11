// Package iam provides Identity and Access Management (IAM) services for simple-idm.
//
// This package manages users, groups, and roles with support for PostgreSQL and
// alternative storage backends through repository interfaces.
//
// # Overview
//
// The iam package provides:
//   - User lifecycle management (create, read, update, delete)
//   - Role-based access control (RBAC)
//   - Group management with user membership
//   - Repository pattern for database abstraction
//   - Support for PostgreSQL and custom backends
//
// # Basic Usage
//
// Creating and using the IAM service:
//
//	import (
//		"github.com/tendant/simple-idm/pkg/iam"
//		"github.com/tendant/simple-idm/pkg/iam/iamdb"
//	)
//
//	// Connect to database
//	db, _ := sql.Open("postgres", connStr)
//	queries := iamdb.New(db)
//
//	// Create repository
//	repo := iam.NewPostgresIamRepository(queries)
//	groupRepo := iam.NewPostgresIamGroupRepository(queries)
//
//	// Create service
//	service := iam.NewIamService(repo, iam.WithGroupRepository(groupRepo))
//
//	// Create a user
//	user, err := service.CreateUser(ctx, "user@example.com", "username", "Full Name", roleIDs, "")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # User Management
//
// Creating and managing users:
//
//	// Create user with roles
//	roleIDs := []uuid.UUID{adminRoleID, userRoleID}
//	user, err := service.CreateUser(ctx, "user@example.com", "jdoe", "John Doe", roleIDs, "")
//
//	// Get user by ID
//	user, err := service.GetUser(ctx, userID)
//
//	// List all users
//	users, err := service.FindUsers(ctx)
//
//	// Update user
//	loginID := uuid.New()
//	user, err := service.UpdateUser(ctx, userID, "Jane Doe", roleIDs, &loginID)
//
//	// Delete user
//	err := service.DeleteUser(ctx, userID)
//
//	// Check if any user exists (useful for first-run setup)
//	exists, err := service.AnyUserExists(ctx)
//	if !exists {
//		// Create admin user
//	}
//
// # Role Management
//
// Managing roles for RBAC:
//
//	// Create a new role
//	roleID, err := service.CreateRole(ctx, "editor")
//
//	// List all roles
//	roles, err := service.FindRoles(ctx)
//	for _, role := range roles {
//		fmt.Printf("Role: %s (ID: %s)\n", role.Name, role.ID)
//	}
//
//	// Users are created with roles
//	roleIDs := []uuid.UUID{editorRoleID}
//	user, err := service.CreateUser(ctx, "editor@example.com", "editor", "Editor User", roleIDs, "")
//
// # Group Management
//
// Managing groups and group membership:
//
//	// Create a group
//	group, err := service.CreateGroup(ctx, "developers", "Development team")
//
//	// List all groups
//	groups, err := service.FindGroups(ctx)
//
//	// Get group by ID
//	group, err := service.GetGroup(ctx, groupID)
//
//	// Update group
//	group, err := service.UpdateGroup(ctx, groupID, "Senior Developers", "Senior dev team")
//
//	// Add user to group
//	err := service.AddUserToGroup(ctx, userID, groupID)
//
//	// List users in group
//	users, err := service.FindGroupUsers(ctx, groupID)
//
//	// Remove user from group
//	err := service.RemoveUserFromGroup(ctx, userID, groupID)
//
//	// Delete group
//	err := service.DeleteGroup(ctx, groupID)
//
//	// Check if group support is available
//	if service.HasGroupSupport() {
//		// Use group features
//	}
//
// # Repository Pattern
//
// The package uses repository interfaces for database abstraction:
//
//	// IamRepository for user and role operations
//	type IamRepository interface {
//		CreateUser(ctx context.Context, params CreateUserParams) (User, error)
//		GetUserWithRoles(ctx context.Context, id uuid.UUID) (UserWithRoles, error)
//		FindUsersWithRoles(ctx context.Context) ([]UserWithRoles, error)
//		UpdateUser(ctx context.Context, params UpdateUserParams) (User, error)
//		DeleteUser(ctx context.Context, id uuid.UUID) error
//		// ... more methods
//	}
//
//	// IamGroupRepository for group operations
//	type IamGroupRepository interface {
//		CreateGroup(ctx context.Context, params CreateGroupParams) (Group, error)
//		FindGroups(ctx context.Context) ([]Group, error)
//		// ... more methods
//	}
//
// # Custom Backend Implementation
//
// Implement repository interfaces for alternative storage:
//
//	type MongoIamRepository struct {
//		client *mongo.Client
//	}
//
//	func (r *MongoIamRepository) CreateUser(ctx context.Context, params iam.CreateUserParams) (iam.User, error) {
//		// MongoDB implementation
//	}
//
//	// Implement all IamRepository methods...
//
//	// Use with IAM service
//	repo := &MongoIamRepository{client: mongoClient}
//	service := iam.NewIamService(repo)
//
// # Data Models
//
// Key types used by the package:
//
//	// User represents a user account
//	type User struct {
//		ID        uuid.UUID
//		Email     string
//		Name      string
//		LoginID   *uuid.UUID
//		CreatedAt time.Time
//		UpdatedAt time.Time
//		DeletedAt *time.Time
//		CreatedBy string
//	}
//
//	// UserWithRoles includes user's assigned roles
//	type UserWithRoles struct {
//		User  User
//		Roles []Role
//	}
//
//	// Role represents a role for RBAC
//	type Role struct {
//		ID   uuid.UUID
//		Name string
//	}
//
//	// Group represents a user group
//	type Group struct {
//		ID          uuid.UUID
//		Name        string
//		Description string
//		CreatedAt   time.Time
//		UpdatedAt   time.Time
//	}
//
// # Integration with Authentication
//
// IAM service is typically used alongside login/auth services:
//
//	// Create user
//	user, err := iamService.CreateUser(ctx, email, username, name, roleIDs, "")
//
//	// Create login credentials (separate package)
//	login, err := loginService.CreateLogin(ctx, email, password)
//
//	// Link user to login
//	user, err = iamService.UpdateUser(ctx, user.ID, name, roleIDs, &login.ID)
//
// # Service Configuration
//
// Configure the service with options:
//
//	service := iam.NewIamService(
//		repo,
//		iam.WithGroupRepository(groupRepo),
//	)
//
// # Error Handling
//
// The package returns standard Go errors:
//
//	user, err := service.GetUser(ctx, userID)
//	if err != nil {
//		if err == sql.ErrNoRows {
//			// User not found
//			return errors.NotFound("user", userID.String())
//		}
//		// Other error
//		return errors.InternalWrap(err, "failed to get user")
//	}
//
// # Testing
//
// Use in-memory repository for testing:
//
//	type MockIamRepository struct {
//		users map[uuid.UUID]iam.User
//		mu    sync.RWMutex
//	}
//
//	func (m *MockIamRepository) GetUserWithRoles(ctx context.Context, id uuid.UUID) (iam.UserWithRoles, error) {
//		m.mu.RLock()
//		defer m.mu.RUnlock()
//
//		user, ok := m.users[id]
//		if !ok {
//			return iam.UserWithRoles{}, sql.ErrNoRows
//		}
//		return iam.UserWithRoles{User: user, Roles: []iam.Role{}}, nil
//	}
//
//	// Use in tests
//	mockRepo := &MockIamRepository{users: make(map[uuid.UUID]iam.User)}
//	service := iam.NewIamService(mockRepo)
//
// # Database Schema
//
// The PostgreSQL implementation expects these tables:
//   - users - User accounts
//   - roles - Available roles
//   - user_roles - User-role assignments (many-to-many)
//   - groups - User groups (optional)
//   - user_groups - User-group memberships (optional)
//
// See migrations/idm_db.sql for complete schema.
//
// # Best Practices
//
// 1. User Creation
//   - Always validate email format before creating users
//   - Assign appropriate default roles
//   - Create login credentials separately
//
// 2. Role Management
//   - Define roles during application bootstrap
//   - Use consistent role names across the application
//   - Check roles in authorization middleware
//
// 3. Group Management
//   - Use groups for team-based permissions
//   - Keep group membership up to date
//   - Check HasGroupSupport() before using group features
//
// 4. Error Handling
//   - Handle sql.ErrNoRows for not found cases
//   - Wrap database errors with context
//   - Use structured errors from pkg/errors
//
// 5. Soft Deletes
//   - Users are soft-deleted (DeletedAt timestamp)
//   - Deleted users are excluded from queries
//   - Physical deletion requires custom repository method
//
// # Common Patterns
//
// Pattern 1: Create user with roles during signup
//
//	func (s *SignupService) RegisterUser(ctx context.Context, email, password, name string) error {
//		// Get default role
//		roles, _ := s.iamService.FindRoles(ctx)
//		defaultRole := findRoleByName(roles, "user")
//
//		// Create user
//		user, err := s.iamService.CreateUser(ctx, email, email, name, []uuid.UUID{defaultRole.ID}, "")
//		if err != nil {
//			return err
//		}
//
//		// Create login credentials
//		login, err := s.loginService.CreateLogin(ctx, email, password)
//		if err != nil {
//			s.iamService.DeleteUser(ctx, user.User.ID) // Rollback
//			return err
//		}
//
//		// Link user to login
//		_, err = s.iamService.UpdateUser(ctx, user.User.ID, name, []uuid.UUID{defaultRole.ID}, &login.ID)
//		return err
//	}
//
// Pattern 2: Check user permissions
//
//	func hasRole(user iam.UserWithRoles, roleName string) bool {
//		for _, role := range user.Roles {
//			if role.Name == roleName {
//				return true
//			}
//		}
//		return false
//	}
//
//	user, err := iamService.GetUser(ctx, userID)
//	if err != nil {
//		return err
//	}
//	if !hasRole(user, "admin") {
//		return errors.Forbidden("admin access required")
//	}
//
// Pattern 3: Batch user operations
//
//	users, err := service.FindUsers(ctx)
//	if err != nil {
//		return err
//	}
//
//	for _, user := range users {
//		if needsUpdate(user) {
//			_, err := service.UpdateUser(ctx, user.User.ID, user.User.Name, getRoleIDs(user.Roles), user.User.LoginID)
//			if err != nil {
//				log.Printf("Failed to update user %s: %v", user.User.ID, err)
//			}
//		}
//	}
//
// # Related Packages
//
//   - pkg/role - Additional role management features
//   - pkg/login - Password-based authentication
//   - pkg/auth - JWT token generation
//   - pkg/signup - User registration
//   - pkg/profile - User profile management
package iam
