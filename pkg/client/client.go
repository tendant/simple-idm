package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

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

// MultiAlgorithmVerifier creates a middleware that can verify tokens using multiple JWTAuth instances
// It tries verifiers in priority order and uses the first one that successfully verifies the token
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
