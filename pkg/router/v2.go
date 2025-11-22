package router

import (
	"github.com/go-chi/chi/v5"
	loginv2 "github.com/tendant/simple-idm/pkg/login/handler/v2"
	signupv2 "github.com/tendant/simple-idm/pkg/signup/handler/v2"
)

// V2Config contains the v2 handlers for authentication and signup
type V2Config struct {
	LoginHandlerV2  *loginv2.Handle
	SignupHandlerV2 *signupv2.Handle
}

// SetupV2Routes mounts the v2 authentication and signup routes
// This follows the pattern from cmd/quick/main.go where routes are explicitly defined
// Example:
//   r.Route("/api/v2/auth", func(r chi.Router) {
//       router.SetupV2Routes(r, v2Config)
//   })
func SetupV2Routes(r chi.Router, cfg V2Config) {
	// Login routes
	if cfg.LoginHandlerV2 != nil {
		r.Post("/login", cfg.LoginHandlerV2.Login)
		r.Post("/logout", cfg.LoginHandlerV2.Logout)
		r.Post("/refresh", cfg.LoginHandlerV2.RefreshToken)
	}

	// Signup route
	if cfg.SignupHandlerV2 != nil {
		r.Post("/signup", cfg.SignupHandlerV2.Signup)
	}
}

// SetupV2AuthRoutes mounts v2 auth routes at the specified prefix
// This is a convenience function that creates the route group and mounts v2 routes
// Example:
//   router.SetupV2AuthRoutes(r, "/api/v2/auth", v2Config)
func SetupV2AuthRoutes(r chi.Router, authPrefix string, cfg V2Config) {
	r.Route(authPrefix, func(r chi.Router) {
		SetupV2Routes(r, cfg)
	})
}
