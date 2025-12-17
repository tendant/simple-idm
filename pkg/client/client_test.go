package client

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CreateTestToken creates a JWT token with the specified user ID and extra claims
// This is useful for testing authentication and authorization
func CreateTestToken(userID string, extraClaims ExtraClaims, secret []byte) (string, error) {
	// Initialize JWT auth with the provided secret
	tokenAuth := jwtauth.New("HS256", secret, nil)

	// Create nested extra claims structure that matches what AuthUserMiddleware expects
	nestedExtraClaims := map[string]interface{}{
		"user_id": userID,
		"extra_claims": map[string]interface{}{
			"usernmae": extraClaims.Username, // Match the typo in the struct tag
			"email":    extraClaims.Email,
			"roles":    extraClaims.Roles,
		},
	}

	// Create JWT claims with the expected structure
	claims := map[string]interface{}{
		"sub":           userID,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"user_id":       userID,
		"extra_claims":  nestedExtraClaims,
	}

	// Create and return the JWT token
	_, tokenString, err := tokenAuth.Encode(claims)
	return tokenString, err
}

func TestCreateTestToken(t *testing.T) {
	// Create a test secret
	secret := []byte("test-jwt-secret-key")

	// Create a user ID
	userID := uuid.New().String()

	// Create extra claims
	extraClaims := ExtraClaims{
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user", "admin"},
	}

	// Create the test token
	tokenString, err := CreateTestToken(userID, extraClaims, secret)
	require.NoError(t, err, "Failed to create test token")
	require.NotEmpty(t, tokenString, "Token string should not be empty")

	t.Logf("Generated test token: %s", tokenString)

	// Initialize JWT auth for verification
	tokenAuth := jwtauth.New("HS256", secret, nil)

	// Verify the token can be parsed
	token, err := tokenAuth.Decode(tokenString)
	require.NoError(t, err, "Failed to decode token")
	require.NotNil(t, token, "Token should not be nil")

	// Get the claims map from the token
	tokenClaims, err := token.AsMap(context.Background())
	require.NoError(t, err, "Failed to get token claims as map")

	// Verify subject claim
	sub, ok := tokenClaims["sub"].(string)
	assert.True(t, ok, "Subject claim should be a string")
	assert.Equal(t, userID, sub, "Subject claim should match user ID")

	// Verify user ID in top-level claims
	userIDFromToken, ok := tokenClaims["user_id"].(string)
	assert.True(t, ok, "User ID should be a string")
	assert.Equal(t, userID, userIDFromToken, "User ID should match")

	// Verify extra claims structure
	extraClaimsTop, ok := tokenClaims["extra_claims"].(map[string]interface{})
	require.True(t, ok, "Extra claims should be a map")

	// Verify user ID in extra claims
	userIDInExtraClaims, ok := extraClaimsTop["user_id"].(string)
	assert.True(t, ok, "User ID in extra claims should be a string")
	assert.Equal(t, userID, userIDInExtraClaims, "User ID in extra claims should match")

	// Verify nested extra claims exist
	extraClaimsNested, ok := extraClaimsTop["extra_claims"].(map[string]interface{})
	require.True(t, ok, "Nested extra claims should be a map")

	// Verify username in nested extra claims (note the typo "usernmae")
	username, ok := extraClaimsNested["usernmae"].(string)
	assert.True(t, ok, "Username should be a string")
	assert.Equal(t, extraClaims.Username, username, "Username should match")

	// Verify email in nested extra claims
	email, ok := extraClaimsNested["email"].(string)
	assert.True(t, ok, "Email should be a string")
	assert.Equal(t, extraClaims.Email, email, "Email should match")

	// Verify roles in nested extra claims
	roles, ok := extraClaimsNested["roles"].([]interface{})
	assert.True(t, ok, "Roles should be an array")
	assert.Len(t, roles, len(extraClaims.Roles), "Roles array length should match")
}

func TestAuthUserMiddleware(t *testing.T) {
	// Create a test secret
	secret := []byte("test-jwt-secret-key")

	// Create a user ID
	userID := uuid.New().String()

	// Create extra claims with different role combinations
	testCases := []struct {
		name        string
		extraClaims ExtraClaims
		expectRoles []string
	}{
		{
			name: "Admin and User Roles",
			extraClaims: ExtraClaims{
				Username: "admin_user",
				Email:    "admin@example.com",
				Roles:    []string{"admin", "user"},
			},
			expectRoles: []string{"admin", "user"},
		},
		{
			name: "User Role Only",
			extraClaims: ExtraClaims{
				Username: "regular_user",
				Email:    "user@example.com",
				Roles:    []string{"user"},
			},
			expectRoles: []string{"user"},
		},
		{
			name: "No Roles",
			extraClaims: ExtraClaims{
				Username: "no_role_user",
				Email:    "norole@example.com",
				Roles:    nil,
			},
			expectRoles: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create token with the test case's extra claims
			tokenString, err := CreateTestToken(userID, tc.extraClaims, secret)
			require.NoError(t, err, "Failed to create test token")

			// Initialize JWT auth for verification
			tokenAuth := jwtauth.New("HS256", secret, nil)

			// Verify the token can be parsed
			token, err := tokenAuth.Decode(tokenString)
			require.NoError(t, err, "Failed to decode token")

			// Create a request context with the token
			ctx := context.Background()
			ctx = jwtauth.NewContext(ctx, token, nil)

			// Create a mock request and response
			req, err := http.NewRequestWithContext(ctx, "GET", "/", nil)
			require.NoError(t, err, "Failed to create request")
			res := &mockResponseWriter{}

			// Create a mock handler that checks if the auth user is in the context
			handlerCalled := false
			mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true

				// Get auth user from context
				authUser, ok := r.Context().Value(AuthUserKey).(*AuthUser)
				assert.True(t, ok, "Auth user should be in the context")
				assert.NotNil(t, authUser, "Auth user should not be nil")

				// Verify auth user properties
				assert.Equal(t, userID, authUser.UserId, "User ID should match")
				assert.Equal(t, tc.extraClaims.Username, authUser.ExtraClaims.Username, "Username should match")
				assert.Equal(t, tc.extraClaims.Email, authUser.ExtraClaims.Email, "Email should match")

				// For the roles, check if both are nil or compare them
				if tc.expectRoles == nil {
					assert.Nil(t, authUser.ExtraClaims.Roles, "Roles should be nil")
				} else {
					assert.Equal(t, tc.expectRoles, authUser.ExtraClaims.Roles, "Roles should match")
					assert.Equal(t, len(tc.expectRoles), len(authUser.ExtraClaims.Roles), "Number of roles should match")
				}
			})

			// Call the middleware
			middleware := AuthUserMiddleware(mockHandler)
			middleware.ServeHTTP(res, req)

			// Verify the handler was called
			assert.True(t, handlerCalled, "Handler should have been called")
			assert.Equal(t, 0, res.statusCode, "Status code should be 0 (not set)")
		})
	}
}

func TestJWTTokenWithCustomClaims(t *testing.T) {
	// Create a test secret
	secret := []byte("test-jwt-secret-key")

	// Initialize JWT auth
	tokenAuth := jwtauth.New("HS256", secret, nil)

	// Create a user ID
	userID := uuid.New().String()

	// Create extra claims
	extraClaims := ExtraClaims{
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user", "admin"},
	}

	// Create nested extra claims structure that matches what AuthUserMiddleware expects
	nestedExtraClaims := map[string]interface{}{
		"user_id": userID,
		"extra_claims": map[string]interface{}{
			"usernmae": extraClaims.Username, // Match the typo in the struct tag
			"email":    extraClaims.Email,
			"roles":    extraClaims.Roles,
		},
	}

	// Create JWT claims with the expected structure
	claims := map[string]interface{}{
		"sub":           userID,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"user_id":       userID,
		"extra_claims":  nestedExtraClaims,
	}

	// Create the JWT token
	_, tokenString, err := tokenAuth.Encode(claims)
	require.NoError(t, err, "Failed to encode token")
	require.NotEmpty(t, tokenString, "Token string should not be empty")

	t.Logf("Generated JWT token: %s", tokenString)

	// Verify the token can be parsed
	token, err := tokenAuth.Decode(tokenString)
	require.NoError(t, err, "Failed to decode token")
	require.NotNil(t, token, "Token should not be nil")

	// Get the claims map from the token
	tokenClaims, err := token.AsMap(context.Background())
	require.NoError(t, err, "Failed to get token claims as map")

	// Verify subject claim
	sub, ok := tokenClaims["sub"].(string)
	assert.True(t, ok, "Subject claim should be a string")
	assert.Equal(t, userID, sub, "Subject claim should match user ID")

	// Verify user ID in top-level claims
	userIDFromToken, ok := tokenClaims["user_id"].(string)
	assert.True(t, ok, "User ID should be a string")
	assert.Equal(t, userID, userIDFromToken, "User ID should match")

	// Verify extra claims structure
	extraClaimsTop, ok := tokenClaims["extra_claims"].(map[string]interface{})
	require.True(t, ok, "Extra claims should be a map")

	// Verify user ID in extra claims
	userIDInExtraClaims, ok := extraClaimsTop["user_id"].(string)
	assert.True(t, ok, "User ID in extra claims should be a string")
	assert.Equal(t, userID, userIDInExtraClaims, "User ID in extra claims should match")

	// Verify nested extra claims
	extraClaimsNested, ok := extraClaimsTop["extra_claims"].(map[string]interface{})
	require.True(t, ok, "Nested extra claims should be a map")

	// Note: The struct has a typo in the tag - "usernmae" instead of "username"
	usernameFromToken, ok := extraClaimsNested["usernmae"].(string)
	assert.True(t, ok, "Username should be a string")
	assert.Equal(t, extraClaims.Username, usernameFromToken, "Username should match")

	// Verify email in nested extra claims
	emailFromToken, ok := extraClaimsNested["email"].(string)
	assert.True(t, ok, "Email should be a string")
	assert.Equal(t, extraClaims.Email, emailFromToken, "Email should match")

	// Verify roles in nested extra claims
	rolesFromToken, ok := extraClaimsNested["roles"].([]interface{})
	assert.True(t, ok, "Roles should be an array")
	assert.Len(t, rolesFromToken, len(extraClaims.Roles), "Roles array length should match")

	// Test the AuthUserMiddleware
	t.Run("TestAuthUserMiddleware", func(t *testing.T) {
		// Create a request context with the token
		ctx := context.Background()
		ctx = jwtauth.NewContext(ctx, token, nil)

		// Create a mock request and response
		req, err := http.NewRequestWithContext(ctx, "GET", "/", nil)
		require.NoError(t, err, "Failed to create request")
		res := &mockResponseWriter{}

		// Create a mock handler that checks if the auth user is in the context
		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			// Get auth user from context
			authUser, ok := r.Context().Value(AuthUserKey).(*AuthUser)
			assert.True(t, ok, "Auth user should be in the context")
			assert.NotNil(t, authUser, "Auth user should not be nil")

			// Verify auth user properties
			assert.Equal(t, userID, authUser.UserId, "User ID should match")
			assert.Equal(t, extraClaims.Username, authUser.ExtraClaims.Username, "Username should match")
			assert.Equal(t, extraClaims.Email, authUser.ExtraClaims.Email, "Email should match")
			assert.Equal(t, extraClaims.Roles, authUser.ExtraClaims.Roles, "Roles should match")
		})

		// Call the middleware
		middleware := AuthUserMiddleware(mockHandler)
		middleware.ServeHTTP(res, req)

		// Verify the handler was called
		assert.True(t, handlerCalled, "Handler should have been called")
		assert.Equal(t, 0, res.statusCode, "Status code should be 0 (not set)")
	})
}

// Mock HTTP response writer for testing
type mockResponseWriter struct {
	statusCode int
	headers    http.Header
	body       []byte
}

func (w *mockResponseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

func (w *mockResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *mockResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

// Tests for AuthContext helper methods

func TestAuthContext_HasScope(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		check    string
		expected bool
	}{
		{"has scope", []string{"openid", "profile", "email"}, "profile", true},
		{"missing scope", []string{"openid", "profile"}, "email", false},
		{"empty scopes", []string{}, "profile", false},
		{"nil scopes", nil, "profile", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AuthContext{Scopes: tc.scopes}
			assert.Equal(t, tc.expected, ac.HasScope(tc.check))
		})
	}
}

func TestAuthContext_HasAnyScope(t *testing.T) {
	ac := &AuthContext{Scopes: []string{"openid", "profile"}}

	assert.True(t, ac.HasAnyScope("profile", "email"))
	assert.True(t, ac.HasAnyScope("email", "openid"))
	assert.False(t, ac.HasAnyScope("email", "groups"))
}

func TestAuthContext_HasAllScopes(t *testing.T) {
	ac := &AuthContext{Scopes: []string{"openid", "profile", "email"}}

	assert.True(t, ac.HasAllScopes("openid", "profile"))
	assert.True(t, ac.HasAllScopes("openid"))
	assert.False(t, ac.HasAllScopes("openid", "groups"))
}

func TestAuthContext_HasRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		check    string
		expected bool
	}{
		{"has role", []string{"admin", "user"}, "admin", true},
		{"missing role", []string{"user"}, "admin", false},
		{"empty roles", []string{}, "admin", false},
		{"nil user", nil, "admin", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ac *AuthContext
			if tc.roles != nil {
				ac = &AuthContext{
					User: &AuthUser{
						ExtraClaims: ExtraClaims{Roles: tc.roles},
					},
				}
			} else {
				ac = &AuthContext{User: nil}
			}
			assert.Equal(t, tc.expected, ac.HasRole(tc.check))
		})
	}
}

func TestAuthContext_HasAnyRole(t *testing.T) {
	ac := &AuthContext{
		User: &AuthUser{
			ExtraClaims: ExtraClaims{Roles: []string{"admin", "user"}},
		},
	}

	assert.True(t, ac.HasAnyRole("admin", "superadmin"))
	assert.True(t, ac.HasAnyRole("viewer", "user"))
	assert.False(t, ac.HasAnyRole("viewer", "superadmin"))

	// Test with nil user
	acNilUser := &AuthContext{User: nil}
	assert.False(t, acNilUser.HasAnyRole("admin"))
}

// Helper function to create a test token with scopes
func createTestTokenWithScopes(userID string, extraClaims ExtraClaims, scopes string, secret []byte) (string, error) {
	tokenAuth := jwtauth.New("HS256", secret, nil)

	nestedExtraClaims := map[string]interface{}{
		"user_id": userID,
		"extra_claims": map[string]interface{}{
			"usernmae": extraClaims.Username,
			"email":    extraClaims.Email,
			"roles":    extraClaims.Roles,
		},
	}

	claims := map[string]interface{}{
		"sub":          userID,
		"exp":          time.Now().Add(time.Hour).Unix(),
		"user_id":      userID,
		"extra_claims": nestedExtraClaims,
	}

	if scopes != "" {
		claims["scope"] = scopes
	}

	_, tokenString, err := tokenAuth.Encode(claims)
	return tokenString, err
}

func TestAuthMiddleware(t *testing.T) {
	secret := []byte("test-jwt-secret-key")
	userID := uuid.New().String()

	tokenAuth := jwtauth.New("HS256", secret, nil)

	t.Run("valid token sets AuthContext", func(t *testing.T) {
		tokenString, err := createTestTokenWithScopes(userID, ExtraClaims{
			Username: "testuser",
			Email:    "test@example.com",
			Roles:    []string{"admin", "user"},
		}, "openid profile email", secret)
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			authCtx := GetAuthContext(r)
			assert.True(t, authCtx.IsAuthenticated)
			assert.NotNil(t, authCtx.User)
			assert.Equal(t, userID, authCtx.User.UserId)
			assert.Equal(t, []string{"openid", "profile", "email"}, authCtx.Scopes)

			// Backward compatibility - AuthUserKey should also be set
			authUser := GetAuthUser(r)
			assert.NotNil(t, authUser)
			assert.Equal(t, userID, authUser.UserId)
		})

		middleware := AuthMiddleware(VerifierConfig{Name: "test", Auth: tokenAuth, Active: true})
		middleware(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
	})

	t.Run("no token continues as unauthenticated", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			authCtx := GetAuthContext(r)
			assert.False(t, authCtx.IsAuthenticated)
			assert.Nil(t, authCtx.User)
		})

		middleware := AuthMiddleware(VerifierConfig{Name: "test", Auth: tokenAuth, Active: true})
		middleware(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
	})

	t.Run("invalid token continues as unauthenticated", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			authCtx := GetAuthContext(r)
			assert.False(t, authCtx.IsAuthenticated)
		})

		middleware := AuthMiddleware(VerifierConfig{Name: "test", Auth: tokenAuth, Active: true})
		middleware(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
	})
}

func TestRequireAuth(t *testing.T) {
	t.Run("authenticated request proceeds", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User:            &AuthUser{UserId: "test-user"},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireAuth(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, 0, res.statusCode) // Not set means success
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: false,
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireAuth(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
	})

	t.Run("missing AuthContext returns 401", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireAuth(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
	})
}

func TestRequireRole(t *testing.T) {
	t.Run("user with required role proceeds", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User: &AuthUser{
				UserId:      "test-user",
				ExtraClaims: ExtraClaims{Roles: []string{"admin", "user"}},
			},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireRole("admin", "superadmin")(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
	})

	t.Run("user without required role returns 403", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User: &AuthUser{
				UserId:      "test-user",
				ExtraClaims: ExtraClaims{Roles: []string{"user"}},
			},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireRole("admin", "superadmin")(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusForbidden, res.statusCode)
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: false,
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireRole("admin")(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
	})
}

func TestRequireScope(t *testing.T) {
	t.Run("user with required scope proceeds", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User:            &AuthUser{UserId: "test-user"},
			Scopes:          []string{"openid", "profile", "email"},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireScope("profile", "groups")(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
	})

	t.Run("user without required scope returns 403", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User:            &AuthUser{UserId: "test-user"},
			Scopes:          []string{"openid"},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireScope("profile", "email")(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusForbidden, res.statusCode)
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: false,
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireScope("profile")(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
	})
}

func TestRequireAllScopes(t *testing.T) {
	t.Run("user with all required scopes proceeds", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User:            &AuthUser{UserId: "test-user"},
			Scopes:          []string{"openid", "profile", "email"},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireAllScopes("openid", "profile")(mockHandler).ServeHTTP(res, req)

		assert.True(t, handlerCalled)
	})

	t.Run("user missing any required scope returns 403", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User:            &AuthUser{UserId: "test-user"},
			Scopes:          []string{"openid", "profile"},
		})
		req = req.WithContext(ctx)
		res := &mockResponseWriter{}

		handlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		RequireAllScopes("openid", "email")(mockHandler).ServeHTTP(res, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusForbidden, res.statusCode)
	})
}

func TestExtractScopes(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		expected []string
	}{
		{
			name:     "space-separated string",
			claims:   map[string]interface{}{"scope": "openid profile email"},
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "array of strings",
			claims:   map[string]interface{}{"scope": []interface{}{"openid", "profile"}},
			expected: []string{"openid", "profile"},
		},
		{
			name:     "scopes claim (non-standard)",
			claims:   map[string]interface{}{"scopes": []interface{}{"read", "write"}},
			expected: []string{"read", "write"},
		},
		{
			name:     "empty scope string",
			claims:   map[string]interface{}{"scope": ""},
			expected: []string{},
		},
		{
			name:     "no scope claim",
			claims:   map[string]interface{}{},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractScopes(tc.claims)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetAuthContext(t *testing.T) {
	t.Run("returns AuthContext when present", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		expected := &AuthContext{
			IsAuthenticated: true,
			User:            &AuthUser{UserId: "test-user"},
		}
		ctx := context.WithValue(req.Context(), AuthContextKey, expected)
		req = req.WithContext(ctx)

		result := GetAuthContext(req)
		assert.Equal(t, expected, result)
	})

	t.Run("returns empty AuthContext when not present", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)

		result := GetAuthContext(req)
		assert.NotNil(t, result)
		assert.False(t, result.IsAuthenticated)
		assert.Nil(t, result.User)
	})
}

func TestGetAuthUser(t *testing.T) {
	t.Run("returns AuthUser from AuthUserKey", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		expected := &AuthUser{UserId: "test-user"}
		ctx := context.WithValue(req.Context(), AuthUserKey, expected)
		req = req.WithContext(ctx)

		result := GetAuthUser(req)
		assert.Equal(t, expected, result)
	})

	t.Run("falls back to AuthContext.User", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		expected := &AuthUser{UserId: "test-user"}
		ctx := context.WithValue(req.Context(), AuthContextKey, &AuthContext{
			IsAuthenticated: true,
			User:            expected,
		})
		req = req.WithContext(ctx)

		result := GetAuthUser(req)
		assert.Equal(t, expected, result)
	})

	t.Run("returns nil when neither present", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)

		result := GetAuthUser(req)
		assert.Nil(t, result)
	})
}
