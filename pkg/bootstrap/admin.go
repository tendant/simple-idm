package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/user"
)

// AdminBootstrapConfig contains configuration for bootstrapping admin roles and user
type AdminBootstrapConfig struct {
	// Admin role names (from ADMIN_ROLE_NAMES env var)
	AdminRoleNames []string

	// Admin user credentials (from ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD)
	AdminUsername string
	AdminEmail    string
	AdminPassword string

	// Service dependencies
	IamService  *iam.IamService
	UserService *user.UserService
}

// AdminUserConfig contains configuration for bootstrapping just the admin user
type AdminUserConfig struct {
	Username      string
	Email         string
	Password      string
	AdminRoleName string
	AdminRoleID   uuid.UUID
}

// AdminRoleInfo contains information about a bootstrapped admin role
type AdminRoleInfo struct {
	ID      uuid.UUID
	Name    string
	Created bool // true if created, false if already existed
}

// AdminBootstrapResult contains the result of admin bootstrap operation
type AdminBootstrapResult struct {
	// Roles that were ensured (created or found)
	Roles []AdminRoleInfo

	// Primary admin role (first in list)
	PrimaryRole AdminRoleInfo

	// Created user information
	UserID       uuid.UUID
	LoginID      uuid.UUID
	Username     string
	Email        string
	Password     string // Only populated if auto-generated
	UserCreated  bool   // true if user was created, false if skipped

	// Password was provided via environment variable
	PasswordFromEnv bool
}

// AdminRolesResult contains the result of admin roles bootstrap
type AdminRolesResult struct {
	// Roles that were ensured (created or found)
	Roles []AdminRoleInfo

	// Primary admin role (first in list)
	PrimaryRole AdminRoleInfo
}

// AdminUserResult contains the result of admin user bootstrap
type AdminUserResult struct {
	UserID          uuid.UUID
	LoginID         uuid.UUID
	Username        string
	Email           string
	Password        string // Only populated if auto-generated
	UserCreated     bool   // true if user was created, false if skipped
	PasswordFromEnv bool
}

// BootstrapAdminRolesAndUser ensures admin roles exist and creates the first admin user if needed
// Returns detailed result about what was created/found, or error if bootstrap fails
func BootstrapAdminRolesAndUser(ctx context.Context, cfg AdminBootstrapConfig) (*AdminBootstrapResult, error) {
	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid bootstrap configuration: %w", err)
	}

	// Check if any users exist - skip bootstrap if they do
	exists, err := cfg.IamService.AnyUserExists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check if users exist: %w", err)
	}

	if exists {
		slog.Info("Users already exist - skipping admin bootstrap")
		return &AdminBootstrapResult{UserCreated: false}, nil
	}

	slog.Info("No users exist - starting admin bootstrap",
		"admin_roles", cfg.AdminRoleNames)

	// Ensure all admin roles exist
	roleInfos, err := ensureAdminRoles(ctx, cfg.IamService, cfg.AdminRoleNames)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure admin roles: %w", err)
	}

	// Primary role is the first one (used for admin user)
	primaryRole := roleInfos[0]

	// Create admin user with primary role
	userResult, err := createAdminUser(ctx, cfg.UserService, primaryRole, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	// Build complete result
	result := &AdminBootstrapResult{
		Roles:           roleInfos,
		PrimaryRole:     primaryRole,
		UserID:          userResult.UserID,
		LoginID:         userResult.LoginID,
		Username:        userResult.Username,
		Email:           userResult.Email,
		Password:        userResult.Password,
		UserCreated:     true,
		PasswordFromEnv: cfg.AdminPassword != "",
	}

	slog.Info("Admin bootstrap completed successfully",
		"roles_created", countCreated(roleInfos),
		"user_created", true,
		"username", result.Username)

	return result, nil
}

// validateConfig validates the bootstrap configuration
func validateConfig(cfg AdminBootstrapConfig) error {
	if len(cfg.AdminRoleNames) == 0 {
		return fmt.Errorf("at least one admin role name is required")
	}

	if cfg.IamService == nil {
		return fmt.Errorf("IamService is required")
	}

	if cfg.UserService == nil {
		return fmt.Errorf("UserService is required")
	}

	return nil
}

// ensureAdminRoles ensures all admin roles exist, creating them if necessary
func ensureAdminRoles(ctx context.Context, iamService *iam.IamService, roleNames []string) ([]AdminRoleInfo, error) {
	// Get all existing roles
	existingRoles, err := iamService.FindRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to find existing roles: %w", err)
	}

	// Build map of existing role names (case-insensitive)
	existingMap := make(map[string]uuid.UUID)
	for _, role := range existingRoles {
		existingMap[strings.ToLower(role.Name)] = role.ID
	}

	// Ensure each admin role exists
	roleInfos := make([]AdminRoleInfo, 0, len(roleNames))

	for _, roleName := range roleNames {
		roleNameLower := strings.ToLower(roleName)

		// Check if role already exists
		if roleID, exists := existingMap[roleNameLower]; exists {
			slog.Info("Admin role already exists", "role", roleName, "id", roleID)
			roleInfos = append(roleInfos, AdminRoleInfo{
				ID:      roleID,
				Name:    roleName,
				Created: false,
			})
			continue
		}

		// Create new role
		roleID, err := iamService.CreateRole(ctx, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to create admin role %s: %w", roleName, err)
		}

		slog.Info("Admin role created", "role", roleName, "id", roleID)
		roleInfos = append(roleInfos, AdminRoleInfo{
			ID:      roleID,
			Name:    roleName,
			Created: true,
		})
	}

	return roleInfos, nil
}

// createAdminUser creates the admin user with the primary role
func createAdminUser(ctx context.Context, userService *user.UserService, primaryRole AdminRoleInfo, cfg AdminBootstrapConfig) (*user.CreateAdminUserResult, error) {
	options := user.CreateAdminUserOptions{
		Username:      cfg.AdminUsername,
		Email:         cfg.AdminEmail,
		Password:      cfg.AdminPassword,
		AdminRoleName: primaryRole.Name,
	}

	result, err := userService.CreateAdminUser(ctx, options)
	if err != nil {
		return nil, err
	}

	slog.Info("Admin user created",
		"username", result.Username,
		"email", result.Email,
		"user_id", result.UserID,
		"login_id", result.LoginID,
		"role", primaryRole.Name)

	return result, nil
}

// countCreated counts how many roles were created (vs already existed)
func countCreated(roles []AdminRoleInfo) int {
	count := 0
	for _, role := range roles {
		if role.Created {
			count++
		}
	}
	return count
}

// BootstrapAdminRoles ensures admin roles exist (can run safely multiple times)
// Returns information about roles that were created or found
func BootstrapAdminRoles(ctx context.Context, iamService *iam.IamService, roleNames []string) (*AdminRolesResult, error) {
	if len(roleNames) == 0 {
		return nil, fmt.Errorf("at least one admin role name is required")
	}

	if iamService == nil {
		return nil, fmt.Errorf("IamService is required")
	}

	slog.Info("Bootstrapping admin roles", "roles", roleNames)

	// Ensure all admin roles exist
	roleInfos, err := ensureAdminRoles(ctx, iamService, roleNames)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure admin roles: %w", err)
	}

	result := &AdminRolesResult{
		Roles:       roleInfos,
		PrimaryRole: roleInfos[0],
	}

	return result, nil
}

// BootstrapAdminUser creates the first admin user if no users exist
// Returns information about the user that was created, or skipped if users already exist
func BootstrapAdminUser(ctx context.Context, iamService *iam.IamService, userService *user.UserService, cfg AdminUserConfig) (*AdminUserResult, error) {
	if iamService == nil {
		return nil, fmt.Errorf("IamService is required")
	}

	if userService == nil {
		return nil, fmt.Errorf("UserService is required")
	}

	// Check if any users exist - skip bootstrap if they do
	exists, err := iamService.AnyUserExists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check if users exist: %w", err)
	}

	if exists {
		slog.Info("Users already exist - skipping admin user creation")
		return &AdminUserResult{UserCreated: false}, nil
	}

	slog.Info("No users exist - creating admin user",
		"username", cfg.Username,
		"role", cfg.AdminRoleName)

	// Create admin user
	options := user.CreateAdminUserOptions{
		Username:      cfg.Username,
		Email:         cfg.Email,
		Password:      cfg.Password,
		AdminRoleName: cfg.AdminRoleName,
	}

	userResult, err := userService.CreateAdminUser(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	result := &AdminUserResult{
		UserID:          userResult.UserID,
		LoginID:         userResult.LoginID,
		Username:        userResult.Username,
		Email:           userResult.Email,
		Password:        userResult.Password,
		UserCreated:     true,
		PasswordFromEnv: cfg.Password != "",
	}

	slog.Info("Admin user created successfully",
		"username", result.Username,
		"user_id", result.UserID,
		"login_id", result.LoginID)

	return result, nil
}
