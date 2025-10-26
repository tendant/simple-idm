package config

import "strings"

// ParseAdminRoleNames parses a comma-separated list of admin role names
// Returns a slice of trimmed, non-empty role names
// Default roles if empty: ["admin", "superadmin"]
func ParseAdminRoleNames(envValue string) []string {
	// Use default if not provided
	if envValue == "" {
		return []string{"admin", "superadmin"}
	}

	parts := strings.Split(envValue, ",")
	roles := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			roles = append(roles, trimmed)
		}
	}

	// Fallback to default if all values were empty
	if len(roles) == 0 {
		return []string{"admin", "superadmin"}
	}

	return roles
}

// IsAdminRole checks if the given role is in the list of admin roles
// Performs case-insensitive comparison
func IsAdminRole(role string, adminRoles []string) bool {
	roleLower := strings.ToLower(role)

	for _, adminRole := range adminRoles {
		if strings.ToLower(adminRole) == roleLower {
			return true
		}
	}

	return false
}

// GetPrimaryAdminRole returns the first role from the admin roles list
// This is used when creating the initial admin role during bootstrap
func GetPrimaryAdminRole(adminRoles []string) string {
	if len(adminRoles) == 0 {
		return "admin" // Fallback
	}
	return adminRoles[0]
}

// HasAnyAdminRole checks if the user has any of the specified admin roles
// Returns true if any role in userRoles matches any role in adminRoles
func HasAnyAdminRole(userRoles []string, adminRoles []string) bool {
	for _, userRole := range userRoles {
		if IsAdminRole(userRole, adminRoles) {
			return true
		}
	}
	return false
}
