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

	// Create custom claims with user ID and extra claims
	customClaims := map[string]interface{}{
		"user_id":      userID,
		"extra_claims": extraClaims,
	}

	// Create JWT claims with expiration (1 hour)
	claims := map[string]interface{}{
		"sub":           userID,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"custom_claims": customClaims,
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

	// Verify custom claims
	customClaimsFromToken, ok := tokenClaims["custom_claims"].(map[string]interface{})
	require.True(t, ok, "Custom claims should be a map")

	// Verify user ID in custom claims
	userIDFromToken, ok := customClaimsFromToken["user_id"].(string)
	assert.True(t, ok, "User ID should be a string")
	assert.Equal(t, userID, userIDFromToken, "User ID in custom claims should match")
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

	// Create custom claims
	customClaims := map[string]interface{}{
		"user_id":      userID,
		"extra_claims": extraClaims,
	}

	// Create JWT claims with expiration
	claims := map[string]interface{}{
		"sub":           userID,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"custom_claims": customClaims,
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

	// Verify custom claims
	customClaimsFromToken, ok := tokenClaims["custom_claims"].(map[string]interface{})
	require.True(t, ok, "Custom claims should be a map")

	// Verify user ID in custom claims
	userIDFromToken, ok := customClaimsFromToken["user_id"].(string)
	assert.True(t, ok, "User ID should be a string")
	assert.Equal(t, userID, userIDFromToken, "User ID in custom claims should match")

	// Verify extra claims
	extraClaimsFromToken, ok := customClaimsFromToken["extra_claims"].(map[string]interface{})
	require.True(t, ok, "Extra claims should be a map")

	// Note: The struct has a typo in the tag - "usernmae" instead of "username"
	usernameFromToken, ok := extraClaimsFromToken["usernmae"].(string)
	assert.True(t, ok, "Username should be a string")
	assert.Equal(t, extraClaims.Username, usernameFromToken, "Username should match")

	// Verify email in extra claims
	emailFromToken, ok := extraClaimsFromToken["email"].(string)
	assert.True(t, ok, "Email should be a string")
	assert.Equal(t, extraClaims.Email, emailFromToken, "Email should match")

	// Verify roles in extra claims
	rolesFromToken, ok := extraClaimsFromToken["roles"].([]interface{})
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
