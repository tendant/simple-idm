package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm/pkg/client"
)

// SecureHandler creates an http.Handler with routing matching OpenAPI spec
// and adds admin role check middleware to all routes
func SecureHandler(si ServerInterface, opts ...ServerOption) http.Handler {
	// First get the standard handler
	handler := Handler(si, opts...)

	// Create a new router that will wrap the standard handler with our admin middleware
	r := chi.NewRouter()

	// Apply the admin role middleware and then mount the standard handler
	r.Group(func(r chi.Router) {
		r.Use(client.AdminRoleMiddleware)
		r.Mount("/", handler)
	})

	return r
}
