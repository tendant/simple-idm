package login

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
)

type AuthUser struct {
	UserId string   `json:"user_id,omitempty"`
	Roles  []string `json:"role,omitempty"`
	// For backward compatibility, we still need to support UserUuid, also it is convenient to have it as a uuid.UUID
	UserUuid uuid.UUID
}

func (i AuthUser) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("user", i.UserId),
		slog.Any("role", i.Roles),
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
		_, claims, err := jwtauth.FromContext(r.Context())
		slog.Info("claims", "claims", claims)
		if err != nil {
			em := fmt.Errorf("missing jwt: %w", err)
			http.Error(w, em.Error(), http.StatusUnauthorized)
			return
		}
		authUser := new(AuthUser)

		customClaims, ok := claims["custom_claims"].(map[string]interface{})
		slog.Info("customClaims", "custom", customClaims)
		if !ok {
			em := fmt.Errorf("missing claims: %w", err)
			http.Error(w, em.Error(), http.StatusUnauthorized)
			return
		}
		err = LoadFromMap(customClaims, authUser)
		if err != nil {
			em := fmt.Errorf("invalid claims: %w", err)
			http.Error(w, em.Error(), http.StatusUnauthorized)
			return
		}

		slog.Info("load claims", "claims", claims)

		err = LoadFromMap(claims, authUser)
		slog.Info("authUser", "user", authUser)
		if err != nil {
			em := fmt.Errorf("invalid claims: %w", err)
			http.Error(w, em.Error(), http.StatusUnauthorized)
			return
		}
		if authUser.UserId == "" {
			http.Error(w, "missing user id", http.StatusUnauthorized)
			return
		}
		authUser.UserUuid, err = uuid.Parse(authUser.UserId)
		if err != nil {
			slog.Warn("failed to parse user id", "err", err)
			//http.Error(w, "invalid user id", http.StatusUnauthorized)
		}

		slog.Info("AdminUserMiddleware", "userId", authUser.UserId, "roles", authUser.Roles)
		// create new context from `r` request context, and assign key `"user"`
		// to value of `"123"`
		ctx := context.WithValue(r.Context(), AuthUserKey, authUser)

		// call the next handler in the chain, passing the response writer and
		// the updated request object with the new context value.
		//
		// note: context.Context values are nested, so any previously set
		// values will be accessible as well, and the new `"user"` key
		// will be accessible from this point forward.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Verifier(ja *jwtauth.JWTAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return jwtauth.Verify(ja, jwtauth.TokenFromHeader, TokenFromCookie)(next)
	}
}

func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("accessToken")
	if err != nil {
		return ""
	}
	return cookie.Value
}
