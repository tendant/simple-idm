package router

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/tendant/simple-idm/pkg/client"
	pkgconfig "github.com/tendant/simple-idm/pkg/config"
	deviceapi "github.com/tendant/simple-idm/pkg/device/api"
	emailverificationapi "github.com/tendant/simple-idm/pkg/emailverification/api"
	externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"
	iamapi "github.com/tendant/simple-idm/pkg/iam/api"
	loginapi "github.com/tendant/simple-idm/pkg/login/api"
	"github.com/tendant/simple-idm/pkg/logins"
	oauth2clientapi "github.com/tendant/simple-idm/pkg/oauth2client/api"
	oidcapi "github.com/tendant/simple-idm/pkg/oidc/api"
	profileapi "github.com/tendant/simple-idm/pkg/profile/api"
	roleapi "github.com/tendant/simple-idm/pkg/role/api"
	sessionsapi "github.com/tendant/simple-idm/pkg/sessions/api"
	"github.com/tendant/simple-idm/pkg/signup"
	twofaapi "github.com/tendant/simple-idm/pkg/twofa/api"
	"github.com/tendant/simple-idm/pkg/wellknown"
)

// Config holds all the dependencies and handlers needed to setup routes
type Config struct {
	// Prefix configuration for all routes
	PrefixConfig pkgconfig.PrefixConfig

	// Handlers for each feature (all pointers)
	LoginHandle             loginapi.Handle
	SignupHandle            signup.Handle
	OIDCHandle              *oidcapi.OidcHandle
	ExternalProviderHandle  *externalProviderAPI.Handle
	EmailVerificationHandle emailverificationapi.Handler
	ProfileHandle           profileapi.Handle
	UserHandle              iamapi.Handle
	RoleHandle              *roleapi.Handle
	TwoFaHandle             *twofaapi.Handle
	DeviceHandle            *deviceapi.DeviceHandler
	LoginsHandle            *logins.LoginsHandle
	OAuth2ClientHandle      *oauth2clientapi.Handle
	SessionHandle           *sessionsapi.Handler // Optional: can be nil

	// Well-known configuration
	WellKnownHandler wellknown.Handler

	// JWT authentication
	RSAAuth  *jwtauth.JWTAuth
	HMACAuth *jwtauth.JWTAuth

	// GetMe service function
	GetMeFunc func(r *http.Request) (interface{}, error)

	// Session management (optional)
	SessionEnabled bool
	SessionPrefix  string

	// V2 handlers (optional - for applications that want to use v2 routes)
	V2 V2Config
}

// SetupRoutes mounts all IDM routes on the provided router
func SetupRoutes(router chi.Router, cfg Config) {
	// Register well-known endpoints (public, no authentication required)
	router.Get("/.well-known/oauth-protected-resource", cfg.WellKnownHandler.ProtectedResourceMetadata)
	router.Get("/.well-known/oauth-authorization-server", cfg.WellKnownHandler.AuthorizationServerMetadata)
	router.Get("/.well-known/openid-configuration", cfg.WellKnownHandler.OpenIDConfiguration)

	// Mount public routes (no authentication required)
	// Skip mounting if prefix is empty (allows applications to mount v2 handlers separately)
	if cfg.PrefixConfig.Auth != "" {
		router.Mount(cfg.PrefixConfig.Auth, loginapi.Handler(cfg.LoginHandle))
	}
	if cfg.PrefixConfig.Signup != "" {
		router.Mount(cfg.PrefixConfig.Signup, signup.Handler(cfg.SignupHandle))
	}
	if cfg.PrefixConfig.OAuth2 != "" {
		router.Mount(cfg.PrefixConfig.OAuth2, oidcapi.Handler(cfg.OIDCHandle))
	}
	if cfg.PrefixConfig.External != "" {
		router.Mount(cfg.PrefixConfig.External, externalProviderAPI.Handler(cfg.ExternalProviderHandle))
	}

	// Mount email verification endpoints (verify is public, resend and status require auth)
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
					slog.Error("Failed getting me", "err", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				render.JSON(w, r, result)
			})
		}

		// Private endpoint for testing authentication
		r.Get("/private", func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, http.StatusText(http.StatusOK))
		})

		// Mount authenticated feature routes
		r.Mount(cfg.PrefixConfig.Profile, profileapi.Handler(cfg.ProfileHandle))
		r.Mount(cfg.PrefixConfig.TwoFA, twofaapi.TwoFaHandler(cfg.TwoFaHandle))
		r.Mount(cfg.PrefixConfig.Device, deviceapi.Handler(cfg.DeviceHandle))

		// Admin-only routes
		r.Mount(cfg.PrefixConfig.Users, iamapi.SecureHandler(cfg.UserHandle))

		// Roles with admin middleware
		roleRouter := chi.NewRouter()
		roleRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", roleapi.Handler(cfg.RoleHandle))
		})
		r.Mount(cfg.PrefixConfig.Roles, roleRouter)

		// Logins with admin middleware
		loginsRouter := chi.NewRouter()
		loginsRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", logins.Handler(cfg.LoginsHandle))
		})
		r.Mount(cfg.PrefixConfig.Logins, loginsRouter)

		// OAuth2 clients with admin middleware
		oauth2ClientRouter := chi.NewRouter()
		oauth2ClientRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", oauth2clientapi.Handler(cfg.OAuth2ClientHandle))
		})
		r.Mount(cfg.PrefixConfig.OAuth2Clients, oauth2ClientRouter)

		// Session management (optional)
		if cfg.SessionEnabled && cfg.SessionHandle != nil {
			sessionPrefix := cfg.SessionPrefix
			if sessionPrefix == "" {
				sessionPrefix = cfg.PrefixConfig.Profile + "/sessions"
			}

			sessionRouter := chi.NewRouter()
			cfg.SessionHandle.RegisterRoutes(sessionRouter)
			r.Mount(sessionPrefix, sessionRouter)

			slog.Info("Session management routes mounted", "prefix", sessionPrefix)
		}
	})
}

// SetupPublicRoutes mounts only public routes (no authentication required)
func SetupPublicRoutes(router chi.Router, cfg Config) {
	// Well-known endpoints
	router.Get("/.well-known/oauth-protected-resource", cfg.WellKnownHandler.ProtectedResourceMetadata)
	router.Get("/.well-known/oauth-authorization-server", cfg.WellKnownHandler.AuthorizationServerMetadata)
	router.Get("/.well-known/openid-configuration", cfg.WellKnownHandler.OpenIDConfiguration)

	// Public API routes
	router.Mount(cfg.PrefixConfig.Auth, loginapi.Handler(cfg.LoginHandle))
	router.Mount(cfg.PrefixConfig.Signup, signup.Handler(cfg.SignupHandle))
	router.Mount(cfg.PrefixConfig.OAuth2, oidcapi.Handler(cfg.OIDCHandle))
	router.Mount(cfg.PrefixConfig.External, externalProviderAPI.Handler(cfg.ExternalProviderHandle))

	// Email verification (verify endpoint only)
	router.Route(cfg.PrefixConfig.Email, func(r chi.Router) {
		r.Post("/verify", cfg.EmailVerificationHandle.VerifyEmail)
	})
}

// SetupAuthenticatedRoutes mounts only authenticated routes
func SetupAuthenticatedRoutes(router chi.Router, cfg Config) {
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
					slog.Error("Failed getting me", "err", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				render.JSON(w, r, result)
			})
		}

		// Protected email verification endpoints
		r.Route(cfg.PrefixConfig.Email, func(r chi.Router) {
			r.Post("/resend", cfg.EmailVerificationHandle.ResendVerification)
			r.Get("/status", cfg.EmailVerificationHandle.GetVerificationStatus)
		})

		// Mount authenticated feature routes
		r.Mount(cfg.PrefixConfig.Profile, profileapi.Handler(cfg.ProfileHandle))
		r.Mount(cfg.PrefixConfig.TwoFA, twofaapi.TwoFaHandler(cfg.TwoFaHandle))
		r.Mount(cfg.PrefixConfig.Device, deviceapi.Handler(cfg.DeviceHandle))

		// Admin-only routes
		r.Mount(cfg.PrefixConfig.Users, iamapi.SecureHandler(cfg.UserHandle))

		// Roles with admin middleware
		roleRouter := chi.NewRouter()
		roleRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", roleapi.Handler(cfg.RoleHandle))
		})
		r.Mount(cfg.PrefixConfig.Roles, roleRouter)

		// Logins with admin middleware
		loginsRouter := chi.NewRouter()
		loginsRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", logins.Handler(cfg.LoginsHandle))
		})
		r.Mount(cfg.PrefixConfig.Logins, loginsRouter)

		// OAuth2 clients with admin middleware
		oauth2ClientRouter := chi.NewRouter()
		oauth2ClientRouter.Group(func(r chi.Router) {
			r.Use(client.AdminRoleMiddleware)
			r.Mount("/", oauth2clientapi.Handler(cfg.OAuth2ClientHandle))
		})
		r.Mount(cfg.PrefixConfig.OAuth2Clients, oauth2ClientRouter)

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
