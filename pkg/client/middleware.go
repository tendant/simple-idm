package client

import (
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm/pkg/config"
)

// AdminRoleMiddleware checks if the authenticated user has the admin role
// and denies access if they don't
// DEPRECATED: Use NewAdminRoleMiddleware with configurable role names instead
// This function maintains backward compatibility with hardcoded "admin" and "superadmin"
func AdminRoleMiddleware(next http.Handler) http.Handler {
	return NewAdminRoleMiddleware([]string{"admin", "superadmin"})(next)
}

// NewAdminRoleMiddleware creates a middleware that checks if the authenticated user
// has any of the specified admin roles
func NewAdminRoleMiddleware(adminRoles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the authenticated user from the context
			authUser, ok := r.Context().Value(AuthUserKey).(*AuthUser)
			if !ok {
				slog.Error("Failed to get authenticated user from context")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if the user has any of the admin roles
			hasAdminRole := config.HasAnyAdminRole(authUser.ExtraClaims.Roles, adminRoles)

			if !hasAdminRole {
				slog.Warn("User attempted to access admin-only resource without admin role",
					"userId", authUser.UserId,
					"userRoles", authUser.ExtraClaims.Roles,
					"requiredAdminRoles", adminRoles)
				http.Error(w, "Forbidden: Admin role required", http.StatusForbidden)
				return
			}

			// User has admin role, proceed to the next handler
			next.ServeHTTP(w, r)
		})
	}
}
