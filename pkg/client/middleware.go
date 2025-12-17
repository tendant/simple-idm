package client

import (
	"log/slog"
	"net/http"
)

// RequireAuth is an authorization middleware that requires valid authentication.
// Returns 401 Unauthorized if the request is not authenticated.
// Must be used after AuthMiddleware.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx := GetAuthContext(r)

		if !authCtx.IsAuthenticated {
			slog.Debug("Unauthenticated request to protected resource")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireRole returns a middleware that checks if the authenticated user has any of the specified roles.
// Returns 401 Unauthorized if not authenticated.
// Returns 403 Forbidden if authenticated but missing required role.
// Must be used after AuthMiddleware.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx := GetAuthContext(r)

			if !authCtx.IsAuthenticated {
				slog.Debug("Unauthenticated request to role-protected resource", "requiredRoles", roles)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !authCtx.HasAnyRole(roles...) {
				slog.Warn("User lacks required role",
					"userId", authCtx.User.UserId,
					"userRoles", authCtx.User.ExtraClaims.Roles,
					"requiredRoles", roles)
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireScope returns a middleware that checks if the authenticated user has any of the specified scopes.
// Returns 401 Unauthorized if not authenticated.
// Returns 403 Forbidden if authenticated but missing required scope.
// Must be used after AuthMiddleware.
func RequireScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx := GetAuthContext(r)

			if !authCtx.IsAuthenticated {
				slog.Debug("Unauthenticated request to scope-protected resource", "requiredScopes", scopes)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !authCtx.HasAnyScope(scopes...) {
				slog.Warn("User lacks required scope",
					"userId", authCtx.User.UserId,
					"userScopes", authCtx.Scopes,
					"requiredScopes", scopes)
				http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllScopes returns a middleware that checks if the authenticated user has ALL of the specified scopes.
// Returns 401 Unauthorized if not authenticated.
// Returns 403 Forbidden if authenticated but missing any required scope.
// Must be used after AuthMiddleware.
func RequireAllScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx := GetAuthContext(r)

			if !authCtx.IsAuthenticated {
				slog.Debug("Unauthenticated request to scope-protected resource", "requiredScopes", scopes)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !authCtx.HasAllScopes(scopes...) {
				slog.Warn("User lacks all required scopes",
					"userId", authCtx.User.UserId,
					"userScopes", authCtx.Scopes,
					"requiredScopes", scopes)
				http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AdminRoleMiddleware checks if the authenticated user has the admin role
// and denies access if they don't
// DEPRECATED: Use RequireRole("admin", "superadmin") instead
// This function maintains backward compatibility with hardcoded "admin" and "superadmin"
func AdminRoleMiddleware(next http.Handler) http.Handler {
	return RequireRole("admin", "superadmin")(next)
}

// NewAdminRoleMiddleware creates a middleware that checks if the authenticated user
// has any of the specified admin roles
// DEPRECATED: Use RequireRole(roles...) instead
func NewAdminRoleMiddleware(adminRoles []string) func(http.Handler) http.Handler {
	return RequireRole(adminRoles...)
}
