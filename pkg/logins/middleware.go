package logins

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm/pkg/iam"
)

// SecureHandler wraps the logins handler with the IAM AdminRoleMiddleware
// to ensure only users with admin roles can access the logins API
func SecureHandler(si ServerInterface) http.Handler {
	// Create a new router
	r := chi.NewRouter()
	
	// Apply the admin role middleware to all routes
	r.Group(func(r chi.Router) {
		r.Use(iam.AdminRoleMiddleware)
		r.Mount("/", Handler(si))
	})
	
	return r
}
