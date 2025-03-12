package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
)

// ExtraClaims holds additional user information in JWT claims
type ExtraClaims struct {
	Username string   `json:"usernmae,omitempty"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// AuthUser represents an authenticated user
type AuthUser struct {
	UserId  string `json:"user_id,omitempty"`
	LoginId string `json:"login_id,omitempty"`
	// For backward compatibility, we still need to support UserUuid, also it is convenient to have it as a uuid.UUID
	UserUuid    uuid.UUID
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

var (
	// AuthUserKey is the context key for the authenticated user
	AuthUserKey = &contextKey{"AuthUser"}
)

// AuthzCheck represents an authorization check result
type AuthzCheck struct {
	IsAllowed bool
}

// LoadFromMap loads a struct from a map
func LoadFromMap[T any](m map[string]interface{}, c *T) error {
	data, err := json.Marshal(m)
	if err == nil {
		err = json.Unmarshal(data, c)
	}
	return err
}

const ACCESS_TOKEN_NAME = "access_token"

// AuthUserMiddleware extracts user information from JWT and adds it to the request context
func AuthUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token and claims from context
		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("missing or invalid JWT: %v", err), http.StatusUnauthorized)
			return
		}

		// Initialize auth user
		authUser := new(AuthUser)

		// Process custom claims if they exist
		if customClaimsRaw, exists := claims["custom_claims"]; exists {
			customClaims, ok := customClaimsRaw.(map[string]interface{})
			if !ok {
				http.Error(w, "invalid custom claims format", http.StatusUnauthorized)
				return
			}

			// Extract data from custom claims
			if err := LoadFromMap(customClaims, authUser); err != nil {
				slog.Error("failed to parse custom claims", "error", err)
				http.Error(w, "invalid custom claims data", http.StatusUnauthorized)
				return
			}

			// Process extra claims if they exist within custom claims
			if extraClaimsRaw, exists := customClaims["extra_claims"]; exists {
				extraClaims, ok := extraClaimsRaw.(map[string]interface{})
				if ok {
					if err := LoadFromMap(extraClaims, &authUser.ExtraClaims); err != nil {
						slog.Warn("failed to parse extra claims", "error", err)
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

		slog.Debug("authenticated user", "userId", authUser.UserId, "roles", authUser.ExtraClaims.Roles)

		// Add auth user to context
		ctx := context.WithValue(r.Context(), AuthUserKey, authUser)

		// Call the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Verifier returns a middleware that verifies JWT tokens
func Verifier(ja *jwtauth.JWTAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return jwtauth.Verify(ja, jwtauth.TokenFromHeader, TokenFromCookie)(next)
	}
}

// TokenFromCookie extracts a JWT token from a cookie
func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(ACCESS_TOKEN_NAME)
	if err != nil {
		return ""
	}
	return cookie.Value
}
