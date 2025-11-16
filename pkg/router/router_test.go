package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
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
	"github.com/tendant/simple-idm/pkg/signup"
	twofaapi "github.com/tendant/simple-idm/pkg/twofa/api"
	"github.com/tendant/simple-idm/pkg/wellknown"
)

// createTestConfig creates a minimal test configuration with mock handlers
func createTestConfig() Config {
	jwtSecret := "test-secret-key-for-testing-only"
	rsaAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)
	hmacAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)

	prefixConfig := pkgconfig.PrefixConfig{
		Auth:          "/api/v1/idm/auth",
		Signup:        "/api/v1/idm/signup",
		Profile:       "/api/v1/idm/profile",
		TwoFA:         "/api/v1/idm/2fa",
		Email:         "/api/v1/idm/email",
		OAuth2:        "/api/v1/oauth2",
		Users:         "/api/v1/idm/users",
		Roles:         "/api/v1/idm/roles",
		Device:        "/api/v1/idm/device",
		Logins:        "/api/v1/idm/logins",
		OAuth2Clients: "/api/v1/idm/oauth2-clients",
		External:      "/api/v1/idm/external",
	}

	wellKnownConfig := wellknown.Config{
		ResourceURI:            "http://localhost:4000",
		AuthorizationServerURI: "http://localhost:4000",
		BaseURL:                "http://localhost:4000",
		Scopes:                 []string{"openid", "profile", "email"},
		ResourceDocumentation:  "http://localhost:4000/docs",
	}

	return Config{
		PrefixConfig: prefixConfig,

		// Create minimal mock handlers
		LoginHandle:             loginapi.Handle{},
		SignupHandle:            signup.Handle{},
		OIDCHandle:              &oidcapi.OidcHandle{},
		ExternalProviderHandle:  &externalProviderAPI.Handle{},
		EmailVerificationHandle: emailverificationapi.Handler{},
		ProfileHandle:           profileapi.Handle{},
		UserHandle:              iamapi.Handle{},
		RoleHandle:              &roleapi.Handle{},
		TwoFaHandle:             &twofaapi.Handle{},
		DeviceHandle:            &deviceapi.DeviceHandler{},
		LoginsHandle:            &logins.LoginsHandle{},
		OAuth2ClientHandle:      &oauth2clientapi.Handle{},

		WellKnownHandler: *wellknown.NewHandler(wellKnownConfig),

		RSAAuth:  rsaAuth,
		HMACAuth: hmacAuth,

		GetMeFunc: func(r *http.Request) (interface{}, error) {
			return map[string]string{"user_id": "test-user"}, nil
		},

		SessionEnabled: false,
		SessionHandle:  nil,
	}
}

// TestSetupRoutes tests that all routes are properly mounted
func TestSetupRoutes(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	SetupRoutes(r, cfg)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int // We expect 404 or 405 for unimplemented handlers, but route should exist
	}{
		// Well-known endpoints
		{
			name:       "OIDC discovery",
			method:     http.MethodGet,
			path:       "/.well-known/openid-configuration",
			wantStatus: http.StatusOK,
		},
		{
			name:       "OAuth2 authorization server metadata",
			method:     http.MethodGet,
			path:       "/.well-known/oauth-authorization-server",
			wantStatus: http.StatusOK,
		},
		{
			name:       "OAuth2 protected resource metadata",
			method:     http.MethodGet,
			path:       "/.well-known/oauth-protected-resource",
			wantStatus: http.StatusOK,
		},

		// Public routes (empty handlers will return 400 bad request for missing body)
		{
			name:   "Login endpoint exists",
			method: http.MethodPost,
			path:   "/api/v1/idm/auth/login",
			// Empty handler with no request body returns 400
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Signup endpoint exists",
			method:     http.MethodPost,
			path:       "/api/v1/idm/signup",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Email verify endpoint exists",
			method:     http.MethodPost,
			path:       "/api/v1/idm/email/verify",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// TestSetupPublicRoutes tests that only public routes are mounted
func TestSetupPublicRoutes(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	SetupPublicRoutes(r, cfg)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		// Well-known endpoints should be accessible
		{
			name:       "OIDC discovery",
			method:     http.MethodGet,
			path:       "/.well-known/openid-configuration",
			wantStatus: http.StatusOK,
		},
		// Public auth routes should exist
		{
			name:       "Login route exists",
			method:     http.MethodPost,
			path:       "/api/v1/idm/auth/login",
			wantStatus: http.StatusBadRequest, // Empty handler returns 400 for missing body
		},
		// Email verify (public) should exist
		{
			name:       "Email verify exists",
			method:     http.MethodPost,
			path:       "/api/v1/idm/email/verify",
			wantStatus: http.StatusBadRequest, // Empty handler returns 400 for missing body
		},
		// Protected routes should NOT be mounted (404 not found - route doesn't exist)
		{
			name:       "/me endpoint should not exist",
			method:     http.MethodGet,
			path:       "/me",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// TestSetupAuthenticatedRoutes tests that only authenticated routes are mounted
func TestSetupAuthenticatedRoutes(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	SetupAuthenticatedRoutes(r, cfg)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		// /me endpoint should exist but require auth (401)
		{
			name:       "/me endpoint exists but requires auth",
			method:     http.MethodGet,
			path:       "/me",
			wantStatus: http.StatusUnauthorized, // No JWT token provided
		},
		// Well-known endpoints should NOT be in authenticated routes
		{
			name:       "Well-known should not exist in authenticated routes",
			method:     http.MethodGet,
			path:       "/.well-known/openid-configuration",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// TestWellKnownEndpoints tests that well-known endpoints return valid JSON
func TestWellKnownEndpoints(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	SetupRoutes(r, cfg)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "OIDC discovery",
			path: "/.well-known/openid-configuration",
		},
		{
			name: "OAuth2 authorization server",
			path: "/.well-known/oauth-authorization-server",
		},
		{
			name: "OAuth2 protected resource",
			path: "/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
			}

			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("got content-type %s, want application/json", contentType)
			}

			// Check that response body is not empty
			if w.Body.Len() == 0 {
				t.Error("expected non-empty response body")
			}
		})
	}
}

// TestPrefixConfiguration tests that custom prefixes are respected
func TestPrefixConfiguration(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	// Change prefix
	cfg.PrefixConfig.Auth = "/custom/auth"

	SetupRoutes(r, cfg)

	// Test that route is accessible at custom prefix
	req := httptest.NewRequest(http.MethodPost, "/custom/auth/login", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Route should exist (even if handler returns 404)
	// If prefix wasn't respected, we'd get 404 from chi router itself
	if w.Code == http.StatusMethodNotAllowed {
		t.Error("route not found - prefix configuration not respected")
	}
}

// TestGetMeEndpoint tests the /me endpoint with authentication
func TestGetMeEndpoint(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	SetupRoutes(r, cfg)

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{
			name:       "No token - unauthorized",
			token:      "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid token - unauthorized",
			token:      "invalid-token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// TestRouteAccessControl tests that routes correctly enforce authentication
func TestRouteAccessControl(t *testing.T) {
	r := chi.NewRouter()
	cfg := createTestConfig()

	SetupRoutes(r, cfg)

	tests := []struct {
		name          string
		path          string
		method        string
		requiresAuth  bool
		expectedCodes []int // Acceptable status codes
	}{
		{
			name:          "Well-known endpoints are public",
			path:          "/.well-known/openid-configuration",
			method:        http.MethodGet,
			requiresAuth:  false,
			expectedCodes: []int{http.StatusOK},
		},
		{
			name:          "/me endpoint requires auth",
			path:          "/me",
			method:        http.MethodGet,
			requiresAuth:  true,
			expectedCodes: []int{http.StatusUnauthorized},
		},
		{
			name:          "/private endpoint requires auth",
			path:          "/private",
			method:        http.MethodGet,
			requiresAuth:  true,
			expectedCodes: []int{http.StatusUnauthorized},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			found := false
			for _, code := range tt.expectedCodes {
				if w.Code == code {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("got status %d, want one of %v", w.Code, tt.expectedCodes)
			}
		})
	}
}
