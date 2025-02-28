package iam

import (
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm/pkg/login"
)

// AdminRoleMiddleware checks if the authenticated user has the admin role
// and denies access if they don't
func AdminRoleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the authenticated user from the context
		authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
		if !ok {
			slog.Error("Failed to get authenticated user from context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the user has the admin role
		hasAdminRole := false
		for _, role := range authUser.ExtraClaims.Roles {
			if role == "admin" || role == "superadmin" {
				hasAdminRole = true
				break
			}
		}

		if !hasAdminRole {
			slog.Warn("User attempted to access admin-only resource without admin role", 
				"userId", authUser.UserId,
				"roles", authUser.ExtraClaims.Roles)
			http.Error(w, "Forbidden: Admin role required", http.StatusForbidden)
			return
		}

		// User has admin role, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}
