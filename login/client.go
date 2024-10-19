package login

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/jwtauth"
	"github.com/google/uuid"
)

type AuthUser struct {
	UserUuid string `json:"user_uuid,omitempty"`
	Role     string `json:"role,omitempty"`
	UserUUID uuid.UUID
}

func (i AuthUser) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("user", i.UserUuid),
		slog.String("role", i.Role),
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
		if err != nil {
			em := fmt.Errorf("missing jwt: %w", err)
			http.Error(w, em.Error(), http.StatusUnauthorized)
			return
		}
		authUser := new(AuthUser)
		err = LoadFromMap(claims, authUser)
		if err != nil {
			em := fmt.Errorf("invalid claims: %w", err)
			http.Error(w, em.Error(), http.StatusUnauthorized)
			return
		}
		if authUser.UserUuid == "" {
			http.Error(w, "missing user uuid", http.StatusUnauthorized)
			return
		}
		authUser.UserUUID, err = uuid.Parse(authUser.UserUuid)
		if err != nil {
			slog.Error("failed to parse user uuid", "err", err)
			http.Error(w, "invalid user uuid", http.StatusUnauthorized)
			return
		}

		customClaims, ok := claims["CustomClaims"].(map[string]interface{})
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

		slog.Info("AdminUserMiddleware", "userUuid", authUser.UserUuid, "role", authUser.Role)
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
