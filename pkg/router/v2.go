package router

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/tendant/simple-idm/pkg/client"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	loginv2 "github.com/tendant/simple-idm/pkg/login/handler/v2"
	"github.com/tendant/simple-idm/pkg/logins"
	oauth2clientapi "github.com/tendant/simple-idm/pkg/oauth2client/api"
	oidcapi "github.com/tendant/simple-idm/pkg/oidc/api"
	profileapi "github.com/tendant/simple-idm/pkg/profile/api"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	signupv2 "github.com/tendant/simple-idm/pkg/signup/handler/v2"
	twofaapi "github.com/tendant/simple-idm/pkg/twofa/api"
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

// SetupV2OnlyRoutes mounts ONLY v2 routes using the PrefixConfig for all endpoints
// This completely replaces SetupRoutes for applications that want v2-only APIs
// Example:
//   router.SetupV2OnlyRoutes(r, cfg)
func SetupV2OnlyRoutes(router chi.Router, cfg Config) {
	// Register well-known endpoints (version-agnostic, always public)
	router.Get("/.well-known/oauth-protected-resource", cfg.WellKnownHandler.ProtectedResourceMetadata)
	router.Get("/.well-known/oauth-authorization-server", cfg.WellKnownHandler.AuthorizationServerMetadata)
	router.Get("/.well-known/openid-configuration", cfg.WellKnownHandler.OpenIDConfiguration)

	// Mount v2 auth routes if v2 handlers are available
	if cfg.V2.LoginHandlerV2 != nil {
		router.Route(cfg.PrefixConfig.Auth, func(r chi.Router) {
			// Use RegisterRoutes to mount all login-related endpoints
			// This includes: login, logout, refresh, magic-link, password-reset
			cfg.V2.LoginHandlerV2.RegisterRoutes(r)
		})
	}

	// Mount v2 signup route if v2 handler is available
	if cfg.V2.SignupHandlerV2 != nil && cfg.PrefixConfig.Signup != "" {
		router.Post(cfg.PrefixConfig.Signup, cfg.V2.SignupHandlerV2.Signup)
	}

	// Mount OAuth2/OIDC endpoints (version-agnostic)
	if cfg.PrefixConfig.OAuth2 != "" {
		router.Mount(cfg.PrefixConfig.OAuth2, oidcapi.Handler(cfg.OIDCHandle))
	}

	// Mount external provider routes (version-agnostic)
	if cfg.PrefixConfig.External != "" {
		router.Mount(cfg.PrefixConfig.External, externalProviderAPI.Handler(cfg.ExternalProviderHandle))
	}

	// Mount email verification endpoints (public verify, protected resend/status)
	if cfg.PrefixConfig.Email != "" {
		router.Route(cfg.PrefixConfig.Email, func(r chi.Router) {
			// Public endpoint for email verification
			r.Post("/verify", cfg.EmailVerificationHandle.VerifyEmail)

			// Protected endpoints requiring authentication
			r.Group(func(r chi.Router) {
				r.Use(jwtauth.Verifier(cfg.RSAAuth))
				r.Use(jwtauth.Authenticator(cfg.RSAAuth))
				r.Post("/resend", cfg.EmailVerificationHandle.ResendVerification)
				r.Get("/status", cfg.EmailVerificationHandle.GetVerificationStatus)
			})
		})
	}

	// Mount authenticated routes
	router.Group(func(r chi.Router) {
		// Setup multi-algorithm JWT verification
		r.Use(client.MultiAlgorithmVerifier(
			client.VerifierConfig{
				Name:   "RSA256-Primary",
				Auth:   cfg.RSAAuth,
				Active: true,
			},
			client.VerifierConfig{
				Name:   "HMAC256-Fallback",
				Auth:   cfg.HMACAuth,
				Active: false,
			},
		))
		r.Use(jwtauth.Authenticator(cfg.RSAAuth))
		r.Use(client.AuthUserMiddleware)

		// /me endpoint
		if cfg.GetMeFunc != nil {
			r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
				result, err := cfg.GetMeFunc(r)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
			})
		}

		// Mount authenticated feature routes
		if cfg.PrefixConfig.Profile != "" {
			r.Mount(cfg.PrefixConfig.Profile, profileapi.Handler(cfg.ProfileHandle))
		}
		if cfg.PrefixConfig.TwoFA != "" {
			r.Mount(cfg.PrefixConfig.TwoFA, twofaapi.TwoFaHandler(cfg.TwoFaHandle))
		}
		if cfg.PrefixConfig.Device != "" {
			r.Mount(cfg.PrefixConfig.Device, deviceapi.Handler(cfg.DeviceHandle))
		}

		// Admin-only routes
		if cfg.PrefixConfig.Users != "" {
			r.Mount(cfg.PrefixConfig.Users, iamapi.SecureHandler(cfg.UserHandle))
		}

		// Roles with admin middleware
		if cfg.PrefixConfig.Roles != "" {
			roleRouter := chi.NewRouter()
			roleRouter.Group(func(r chi.Router) {
				r.Use(client.AdminRoleMiddleware)
				r.Mount("/", roleapi.Handler(cfg.RoleHandle))
			})
			r.Mount(cfg.PrefixConfig.Roles, roleRouter)
		}

		// Logins with admin middleware
		if cfg.PrefixConfig.Logins != "" {
			loginsRouter := chi.NewRouter()
			loginsRouter.Group(func(r chi.Router) {
				r.Use(client.AdminRoleMiddleware)
				r.Mount("/", logins.Handler(cfg.LoginsHandle))
			})
			r.Mount(cfg.PrefixConfig.Logins, loginsRouter)
		}

		// OAuth2 clients with admin middleware
		if cfg.PrefixConfig.OAuth2Clients != "" {
			oauth2ClientRouter := chi.NewRouter()
			oauth2ClientRouter.Group(func(r chi.Router) {
				r.Use(client.AdminRoleMiddleware)
				r.Mount("/", oauth2clientapi.Handler(cfg.OAuth2ClientHandle))
			})
			r.Mount(cfg.PrefixConfig.OAuth2Clients, oauth2ClientRouter)
		}

		// Session management (optional)
		if cfg.SessionEnabled && cfg.SessionHandle != nil {
			sessionPrefix := cfg.SessionPrefix
			if sessionPrefix == "" {
				sessionPrefix = cfg.PrefixConfig.Profile + "/sessions"
			}

			sessionRouter := chi.NewRouter()
			cfg.SessionHandle.RegisterRoutes(sessionRouter)
			r.Mount(sessionPrefix, sessionRouter)
		}
	})
}
