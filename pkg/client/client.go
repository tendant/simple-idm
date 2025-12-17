package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
)

type ExtraClaims struct {
	Username string   `json:"usernmae,omitempty"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

type AuthUser struct {
	UserId      string `json:"user_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"` // Name of the user, not username
	LoginId     string `json:"login_id,omitempty"`
	// For backward compatibility, we still need to support UserUuid, also it is convenient to have it as a uuid.UUID
	UserUuid uuid.UUID
	// LoginID as UUID for direct use (parsed from LoginId string)
	LoginID     uuid.UUID
	ExtraClaims ExtraClaims `json:"extra_claims,omitempty"`
}

func (i AuthUser) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("user", i.UserId),
		slog.Any("extra_claims", i.ExtraClaims),
	)
}

// AuthContext is the single source of truth for authentication state
// It separates authentication (who is this?) from authorization (what can they do?)
type AuthContext struct {
	// User information (nil if not authenticated)
	User *AuthUser

	// OAuth2 scopes extracted from JWT 'scope' claim
	Scopes []string

	// Whether the request has valid authentication
	IsAuthenticated bool

	// Raw JWT claims for extensibility
	Claims map[string]interface{}
}

// HasScope checks if the auth context has a specific scope
func (ac *AuthContext) HasScope(scope string) bool {
	for _, s := range ac.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the auth context has any of the specified scopes
func (ac *AuthContext) HasAnyScope(scopes ...string) bool {
	for _, required := range scopes {
		if ac.HasScope(required) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the auth context has all of the specified scopes
func (ac *AuthContext) HasAllScopes(scopes ...string) bool {
	for _, required := range scopes {
		if !ac.HasScope(required) {
			return false
		}
	}
	return true
}

// HasRole checks if the authenticated user has a specific role
func (ac *AuthContext) HasRole(role string) bool {
	if ac.User == nil {
		return false
	}
	for _, r := range ac.User.ExtraClaims.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the authenticated user has any of the specified roles
func (ac *AuthContext) HasAnyRole(roles ...string) bool {
	if ac.User == nil {
		return false
	}
	for _, required := range roles {
		if ac.HasRole(required) {
			return true
		}
	}
	return false
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "biz context value " + k.name
}

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
)

var (
	// AuthContextKey is the context key for AuthContext
	AuthContextKey = &contextKey{"AuthContext"}
	// AuthUserKey is the context key for AuthUser (DEPRECATED: use AuthContextKey)
	AuthUserKey = &contextKey{"AuthUser"}
)

type AuthzCheck struct {
	IsAllowed bool
}

func LoadFromMap[T any](m map[string]interface{}, c *T) error {
	data, err := json.Marshal(m)
	if err == nil {
		err = json.Unmarshal(data, c)
	}
	return err
}

// AuthUserMiddleware extracts user information from JWT claims and adds to context.
// DEPRECATED: Use AuthMiddleware + RequireAuth instead. AuthMiddleware provides the same
// functionality with better separation of authentication and authorization concerns.
func AuthUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token and claims from context
		// First try our custom context values for multi-algorithm support
		var claims map[string]interface{}
		var err error

		if claimsValue := r.Context().Value("verified_claims"); claimsValue != nil {
			if mapClaims, ok := claimsValue.(map[string]interface{}); ok {
				claims = mapClaims
			}
		}

		// Fallback to jwtauth context if no custom claims found
		if claims == nil {
			_, jwtClaims, jwtErr := jwtauth.FromContext(r.Context())
			if jwtErr != nil {
				http.Error(w, fmt.Sprintf("missing or invalid JWT: %v", jwtErr), http.StatusUnauthorized)
				return
			}
			// Convert jwtauth claims to map[string]interface{}
			if jwtClaims != nil {
				claims = make(map[string]interface{})
				for k, v := range jwtClaims {
					claims[k] = v
				}
			}
		}

		if claims == nil {
			http.Error(w, "missing JWT claims", http.StatusUnauthorized)
			return
		}

		// Initialize auth user
		authUser := new(AuthUser)

		// Process extra claims if they exist
		if extraClaimsRaw, exists := claims["extra_claims"]; exists {
			extraClaims, ok := extraClaimsRaw.(map[string]interface{})
			if !ok {
				http.Error(w, "invalid extra claims format", http.StatusUnauthorized)
				return
			}

			// Extract data from extra claims
			if err := LoadFromMap(extraClaims, authUser); err != nil {
				slog.Error("failed to parse extra claims", "error", err)
				http.Error(w, "invalid extra claims data", http.StatusUnauthorized)
				return
			}

			// Process nested extra claims if they exist within extra claims
			if extraClaimsNestedRaw, exists := extraClaims["extra_claims"]; exists {
				extraClaimsNested, ok := extraClaimsNestedRaw.(map[string]interface{})
				if ok {
					if err := LoadFromMap(extraClaimsNested, &authUser.ExtraClaims); err != nil {
						slog.Warn("failed to parse nested extra claims", "error", err)
						// Continue processing as extra claims are optional
					}
				}
			}
		}

		// Also load standard claims directly from the token
		if err := LoadFromMap(claims, authUser); err != nil {
			slog.Error("failed to parse standard claims", "error", err)
			http.Error(w, "invalid token claims", http.StatusUnauthorized)
			return
		}

		// Validate user ID
		if authUser.UserId == "" {
			http.Error(w, "missing user ID in token", http.StatusUnauthorized)
			return
		}

		// Parse user UUID
		userUUID, err := uuid.Parse(authUser.UserId)
		if err != nil {
			slog.Warn("failed to parse user ID as UUID", "userId", authUser.UserId, "error", err)
			// Continue processing as we have the string version
		} else {
			authUser.UserUuid = userUUID
		}

		// Parse login UUID if present
		if authUser.LoginId != "" {
			loginUUID, err := uuid.Parse(authUser.LoginId)
			if err != nil {
				slog.Warn("failed to parse login ID as UUID", "loginId", authUser.LoginId, "error", err)
				// Continue processing as we have the string version
			} else {
				authUser.LoginID = loginUUID
			}
		}

		slog.Debug("authenticated user", "userId", authUser.UserId, "roles", authUser.ExtraClaims.Roles)

		// Add auth user to context
		ctx := context.WithValue(r.Context(), AuthUserKey, authUser)

		// Call the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Verifier creates a middleware that verifies JWT tokens using a single JWTAuth instance.
// DEPRECATED: Use AuthMiddleware instead, which supports multiple verification algorithms.
func Verifier(ja *jwtauth.JWTAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return jwtauth.Verify(ja, jwtauth.TokenFromHeader, TokenFromCookie, TempTokenFromCookie, TempTokenFromHeader)(next)
	}
}

func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(ACCESS_TOKEN_NAME)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func TempTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(TEMP_TOKEN_NAME)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func TempTokenFromHeader(r *http.Request) string {
	return r.Header.Get(TEMP_TOKEN_NAME)
}

// IsAdmin checks if the user has admin privileges
// IsAdmin checks if the user has hardcoded "admin" or "superadmin" role
// DEPRECATED: Use IsAdminWithRoles for configurable admin role checking
func IsAdmin(user *AuthUser) bool {
	return IsAdminWithRoles(user, []string{"admin", "superadmin"})
}

// IsAdminWithRoles checks if the user has any of the specified admin roles
func IsAdminWithRoles(user *AuthUser, adminRoles []string) bool {
	if user == nil || user.ExtraClaims.Roles == nil {
		return false
	}

	for _, userRole := range user.ExtraClaims.Roles {
		for _, adminRole := range adminRoles {
			if userRole == adminRole {
				return true
			}
		}
	}

	return false
}

// VerifierConfig represents a single verifier configuration
type VerifierConfig struct {
	Name   string           // Name/identifier for this verifier
	Auth   *jwtauth.JWTAuth // The JWTAuth instance
	Active bool             // Whether this verifier is currently active
}

// MultiAlgorithmVerifier creates a middleware that can verify tokens using multiple JWTAuth instances.
// It tries verifiers in priority order and uses the first one that successfully verifies the token.
// DEPRECATED: Use AuthMiddleware instead, which combines token verification and context setup
// into a single middleware with better separation of authentication and authorization.
func MultiAlgorithmVerifier(verifiers ...VerifierConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract token using existing extractors
			tokenString, err := extractTokenFromRequest(r)
			if err != nil {
				slog.Error("Token extraction failed", "error", err)
				// Set empty context values and continue
				ctx = jwtauth.NewContext(ctx, nil, err)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Try each active verifier in priority order
			var lastErr error
			for _, config := range sortVerifiers(verifiers) {
				slog.Info("Trying verifier", "name", config.Name)

				// Try to verify with this verifier
				token, err := jwtauth.VerifyToken(config.Auth, tokenString)
				if err != nil {
					slog.Error("Verifier failed", "name", config.Name, "error", err)
					lastErr = err
					continue
				}
				ctx = jwtauth.NewContext(ctx, token, err)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// All verifiers failed
			slog.Error("All verifiers failed", "lastError", lastErr)
			ctx = jwtauth.NewContext(ctx, nil, lastErr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// getActiveVerifiersByPriority returns only active verifiers sorted by priority
func sortVerifiers(verifiers []VerifierConfig) []VerifierConfig {
	var active []VerifierConfig
	for _, v := range verifiers {
		if v.Active {
			active = append(active, v)
		}
	}

	for _, v := range verifiers {
		if !v.Active {
			active = append(active, v)
		}
	}
	slog.Info("all verifiers", "verifiers", active)

	return active
}

// extractTokenFromRequest attempts to extract a token from the request using existing extractors
func extractTokenFromRequest(r *http.Request) (string, error) {
	// Try to extract token using existing extractors in order of preference
	extractors := []func(*http.Request) string{
		jwtauth.TokenFromHeader,
		TokenFromCookie,
		TempTokenFromCookie,
		TempTokenFromHeader,
	}

	for _, extractor := range extractors {
		if tokenString := extractor(r); tokenString != "" {
			return tokenString, nil
		}
	}

	return "", fmt.Errorf("no token found")
}

// GetAuthContext retrieves the AuthContext from request context
// Returns a non-nil AuthContext with IsAuthenticated=false if not found
func GetAuthContext(r *http.Request) *AuthContext {
	if authCtx, ok := r.Context().Value(AuthContextKey).(*AuthContext); ok {
		return authCtx
	}
	return &AuthContext{
		IsAuthenticated: false,
		User:            nil,
		Scopes:          []string{},
		Claims:          nil,
	}
}

// GetAuthUser retrieves the authenticated user from request context
// DEPRECATED: Use GetAuthContext instead
func GetAuthUser(r *http.Request) *AuthUser {
	if authUser, ok := r.Context().Value(AuthUserKey).(*AuthUser); ok {
		return authUser
	}
	// Fallback to AuthContext
	authCtx := GetAuthContext(r)
	return authCtx.User
}

// AuthMiddleware is the unified authentication middleware
// It extracts tokens, verifies them, and attaches AuthContext to the request
// This middleware does NOT enforce authentication - it just makes auth info available
// Use RequireAuth, RequireRole, or RequireScope for authorization
func AuthMiddleware(verifiers ...VerifierConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract token from request
			tokenString, err := extractTokenFromRequest(r)
			if err != nil {
				// No token found - continue as unauthenticated
				slog.Debug("No token found in request", "error", err)
				authCtx := &AuthContext{
					IsAuthenticated: false,
					User:            nil,
					Scopes:          []string{},
					Claims:          nil,
				}
				ctx = context.WithValue(ctx, AuthContextKey, authCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Try to verify token with each verifier
			var claims map[string]interface{}
			var lastErr error

			for _, config := range sortVerifiers(verifiers) {
				token, err := jwtauth.VerifyToken(config.Auth, tokenString)
				if err != nil {
					slog.Debug("Verifier failed", "name", config.Name, "error", err)
					lastErr = err
					continue
				}

				// Successfully verified - extract claims
				tokenClaims, err := token.AsMap(ctx)
				if err != nil {
					slog.Debug("Failed to extract claims", "name", config.Name, "error", err)
					lastErr = err
					continue
				}

				claims = tokenClaims
				slog.Debug("Token verified successfully", "verifier", config.Name)
				break
			}

			if claims == nil {
				// Verification failed - continue as unauthenticated
				slog.Debug("Token verification failed", "error", lastErr)
				authCtx := &AuthContext{
					IsAuthenticated: false,
					User:            nil,
					Scopes:          []string{},
					Claims:          nil,
				}
				ctx = context.WithValue(ctx, AuthContextKey, authCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Parse AuthUser from claims
			authUser, err := parseAuthUserFromClaims(claims)
			if err != nil {
				slog.Warn("Failed to parse auth user from valid token", "error", err)
				authCtx := &AuthContext{
					IsAuthenticated: false,
					User:            nil,
					Scopes:          []string{},
					Claims:          claims,
				}
				ctx = context.WithValue(ctx, AuthContextKey, authCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Extract OAuth2 scopes from token
			scopes := extractScopes(claims)

			// Create authenticated AuthContext
			authCtx := &AuthContext{
				IsAuthenticated: true,
				User:            authUser,
				Scopes:          scopes,
				Claims:          claims,
			}

			// Attach AuthContext to context
			ctx = context.WithValue(ctx, AuthContextKey, authCtx)

			// For backward compatibility, also set AuthUserKey
			ctx = context.WithValue(ctx, AuthUserKey, authUser)

			slog.Debug("Request authenticated",
				"userId", authUser.UserId,
				"roles", authUser.ExtraClaims.Roles,
				"scopes", scopes)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// parseAuthUserFromClaims extracts AuthUser from JWT claims
func parseAuthUserFromClaims(claims map[string]interface{}) (*AuthUser, error) {
	authUser := new(AuthUser)

	// Process extra claims if they exist
	if extraClaimsRaw, exists := claims["extra_claims"]; exists {
		extraClaims, ok := extraClaimsRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid extra claims format")
		}

		if err := LoadFromMap(extraClaims, authUser); err != nil {
			return nil, fmt.Errorf("failed to parse extra claims: %w", err)
		}

		// Process nested extra claims
		if extraClaimsNestedRaw, exists := extraClaims["extra_claims"]; exists {
			extraClaimsNested, ok := extraClaimsNestedRaw.(map[string]interface{})
			if ok {
				if err := LoadFromMap(extraClaimsNested, &authUser.ExtraClaims); err != nil {
					slog.Warn("failed to parse nested extra claims", "error", err)
				}
			}
		}
	}

	// Load standard claims
	if err := LoadFromMap(claims, authUser); err != nil {
		return nil, fmt.Errorf("failed to parse standard claims: %w", err)
	}

	// Validate user ID
	if authUser.UserId == "" {
		return nil, fmt.Errorf("missing user ID in token")
	}

	// Parse UUIDs
	userUUID, err := uuid.Parse(authUser.UserId)
	if err != nil {
		slog.Warn("failed to parse user ID as UUID", "userId", authUser.UserId, "error", err)
	} else {
		authUser.UserUuid = userUUID
	}

	if authUser.LoginId != "" {
		loginUUID, err := uuid.Parse(authUser.LoginId)
		if err != nil {
			slog.Warn("failed to parse login ID as UUID", "loginId", authUser.LoginId, "error", err)
		} else {
			authUser.LoginID = loginUUID
		}
	}

	return authUser, nil
}

// extractScopes extracts OAuth2 scopes from JWT claims
// Supports 'scope' claim as space-separated string (OAuth2 standard) or array
func extractScopes(claims map[string]interface{}) []string {
	// Try 'scope' claim first (OAuth2 standard)
	if scopeClaim, exists := claims["scope"]; exists {
		switch v := scopeClaim.(type) {
		case string:
			// Space-separated string (OAuth2 standard format)
			if v == "" {
				return []string{}
			}
			return strings.Split(v, " ")
		case []interface{}:
			// Array of scopes
			scopes := make([]string, 0, len(v))
			for _, scope := range v {
				if s, ok := scope.(string); ok {
					scopes = append(scopes, s)
				}
			}
			return scopes
		case []string:
			return v
		}
	}

	// Try 'scopes' claim (non-standard but common)
	if scopesClaim, exists := claims["scopes"]; exists {
		switch v := scopesClaim.(type) {
		case []interface{}:
			scopes := make([]string, 0, len(v))
			for _, scope := range v {
				if s, ok := scope.(string); ok {
					scopes = append(scopes, s)
				}
			}
			return scopes
		case []string:
			return v
		}
	}

	return []string{}
}
