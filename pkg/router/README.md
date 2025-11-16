# Simple IDM Router Package

This package provides reusable route setup for Simple IDM, allowing you to mount all authentication and identity management routes in your own application.

## Usage

### Quick Start (Recommended)

The easiest way to integrate Simple IDM is using `NewMinimalConfig`:

```go
package main

import (
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/tendant/simple-idm/pkg/router"
)

func main() {
    r := chi.NewRouter()

    // Create Simple IDM configuration with sane defaults
    cfg, err := router.NewMinimalConfig(router.MinimalOptions{
        DatabaseURL:         "postgres://user:pwd@localhost:5432/mydb?sslmode=disable",
        JWTSecret:           "your-secret-key",
        BaseURL:             "http://localhost:4000",
        RegistrationEnabled: true,   // Allow user registration
        DefaultRole:         "user", // Default role for new users
    })
    if err != nil {
        log.Fatal(err)
    }

    // Mount all Simple IDM routes
    router.SetupRoutes(r, cfg)

    // Add your application routes
    r.Get("/api/myapp/*", myAppHandler)

    // Start server
    http.ListenAndServe(":4000", r)
}
```

That's it! Just **3 required parameters**:
- `DatabaseURL` - PostgreSQL connection string
- `JWTSecret` - Secret for signing JWT tokens
- `BaseURL` - Base URL of your application

All routes are automatically configured with sensible defaults.

### Advanced Setup

For full control over all handlers and services:

```go
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/tendant/simple-idm/pkg/router"
    // ... other imports
)

func main() {
    // Create your chi router
    r := chi.NewRouter()

    // Initialize all your Simple IDM services (loginService, iamService, etc.)
    // See cmd/loginv2/main.go for complete example

    // Create router configuration
    routerConfig := router.Config{
        PrefixConfig: prefixConfig,

        // Public handlers
        LoginHandle:             loginHandle,
        SignupHandle:            signupHandle,
        OIDCHandle:              oidcHandle,
        ExternalProviderHandle:  externalProviderHandle,
        EmailVerificationHandle: emailVerificationHandle,

        // Authenticated handlers
        ProfileHandle:      profileHandle,
        UserHandle:         userHandle,
        RoleHandle:         roleHandle,
        TwoFaHandle:        twoFaHandle,
        DeviceHandle:       deviceHandle,
        LoginsHandle:       loginsHandle,
        OAuth2ClientHandle: oauth2ClientHandle,

        // Optional session management
        SessionHandle:  sessionHandle, // can be nil
        SessionEnabled: true,
        SessionPrefix:  "/api/v1/idm/profile/sessions",

        // Well-known endpoints
        WellKnownHandler: wellKnownHandler,

        // JWT authentication
        RSAAuth:  rsaAuth,
        HMACAuth: hmacAuth,

        // GetMe function
        GetMeFunc: func(r *http.Request) (interface{}, error) {
            authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
            if !ok {
                return nil, errors.New("not authenticated")
            }
            return loginService.GetMe(r.Context(), authUser.UserUuid)
        },
    }

    // Mount all routes
    router.SetupRoutes(r, routerConfig)

    // Start server
    http.ListenAndServe(":4000", r)
}
```

### Selective Route Mounting

You can also mount only public or authenticated routes:

```go
// Mount only public routes (login, signup, OAuth2, etc.)
router.SetupPublicRoutes(r, routerConfig)

// Mount only authenticated routes (profile, users, roles, etc.)
router.SetupAuthenticatedRoutes(r, routerConfig)
```

## Integration Example for Tripmemo

Here's how tripmemo can integrate Simple IDM routes:

```go
package main

import (
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/tendant/simple-idm/pkg/router"
    // ... Simple IDM imports

    // ... Tripmemo imports
    tripHandlers "github.com/tripmemo/backend/internal/handlers"
)

func main() {
    r := chi.NewRouter()

    // 1. Initialize Simple IDM services
    // (database, login service, IAM service, etc.)
    pool := initDatabase()
    loginService := initLoginService(pool)
    iamService := initIamService(pool)
    // ... initialize all other services

    // 2. Setup Simple IDM routes
    idmConfig := router.Config{
        PrefixConfig: pkgconfig.PrefixConfig{
            Auth:          "/api/v1/idm/auth",
            Signup:        "/api/v1/idm/signup",
            Profile:       "/api/v1/idm/profile",
            OAuth2:        "/api/v1/oauth2",
            Users:         "/api/v1/idm/users",
            // ... other prefixes
        },
        LoginHandle:  loginHandle,
        SignupHandle: signupHandle,
        // ... other handlers
        RSAAuth:  rsaAuth,
        HMACAuth: hmacAuth,
        GetMeFunc: func(r *http.Request) (interface{}, error) {
            authUser, _ := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
            return loginService.GetMe(r.Context(), authUser.UserUuid)
        },
    }

    router.SetupRoutes(r, idmConfig)

    // 3. Setup Tripmemo routes (using same JWT auth)
    r.Group(func(r chi.Router) {
        r.Use(jwtauth.Verifier(rsaAuth))
        r.Use(jwtauth.Authenticator(rsaAuth))
        r.Use(client.AuthUserMiddleware)

        tripHandler := tripHandlers.NewTripHandler(tripService)
        r.Post("/api/v1/trips", tripHandler.CreateTrip)
        r.Get("/api/v1/trips", tripHandler.ListTrips)
        r.Get("/api/v1/trips/{id}", tripHandler.GetTrip)
        // ... other trip routes
    })

    http.ListenAndServe(":8000", r)
}
```

## Configuration

### Prefix Configuration

The `PrefixConfig` allows you to customize where each set of routes is mounted:

```go
prefixConfig := pkgconfig.PrefixConfig{
    Auth:          "/api/v1/idm/auth",          // Login, logout, 2FA
    Signup:        "/api/v1/idm/signup",        // User registration
    Profile:       "/api/v1/idm/profile",       // Profile management
    TwoFA:         "/api/v1/idm/2fa",           // Two-factor auth
    Email:         "/api/v1/idm/email",         // Email verification
    OAuth2:        "/api/v1/oauth2",            // OAuth2/OIDC endpoints
    Users:         "/api/v1/idm/users",         // User management (admin)
    Roles:         "/api/v1/idm/roles",         // Role management (admin)
    Device:        "/api/v1/idm/device",        // Device management
    Logins:        "/api/v1/idm/logins",        // Login sessions (admin)
    OAuth2Clients: "/api/v1/idm/oauth2-clients", // OAuth2 clients (admin)
    External:      "/api/v1/idm/external",      // External OAuth providers
}
```

### JWT Configuration

The router requires both RSA and HMAC JWT authenticators for multi-algorithm support:

```go
// Primary: RSA-256
rsaAuth := jwtauth.New("RS256", privateKey, publicKey)

// Fallback: HMAC-256
hmacAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)
```

## Handler Dependencies

Each handler requires specific services. See `cmd/loginv2/main.go` for the complete initialization example.

### Required Services

- **Database**: PostgreSQL connection pool (`*pgxpool.Pool`)
- **LoginService**: Handles authentication and user lookup
- **IamService**: User and group management
- **RoleService**: Role-based access control
- **TokenService**: JWT token generation
- **TwoFaService**: Two-factor authentication
- **DeviceService**: Device recognition
- **NotificationManager**: Email/SMS notifications
- **OIDCService**: OAuth2/OIDC flows
- **ClientService**: OAuth2 client management

## Features

### Public Routes (No Authentication)

- Login (password, magic link, passwordless)
- User registration
- Email verification (verify endpoint)
- OAuth2/OIDC endpoints (authorize, token, userinfo)
- External OAuth providers (Google, GitHub, Microsoft, LinkedIn)
- Well-known endpoints (OIDC discovery, authorization server metadata)

### Authenticated Routes

- Profile management
- Two-factor authentication setup
- Device management
- Email verification (resend, status)
- Session management (optional)

### Admin Routes

- User management (CRUD)
- Role management (CRUD)
- Login session management
- OAuth2 client management

## Authentication Flow

1. User logs in via `/api/v1/idm/auth/login`
2. Simple IDM validates credentials and generates JWT
3. JWT is returned as HTTP-only cookie
4. Subsequent requests include cookie
5. Router middleware verifies JWT and extracts user info
6. User info available in request context as `client.AuthUser`

## Next Steps

1. Import `github.com/tendant/simple-idm/pkg/router` in your application
2. Initialize Simple IDM services (see `cmd/loginv2/main.go`)
3. Create `router.Config` with all handlers
4. Call `router.SetupRoutes(r, config)`
5. Add your application routes using the same JWT middleware

## Complete Example

See `/Users/admin/workspace/tripmemo/tripmemo-agent/backend/cmd/api/main.go` for a complete integration example with Tripmemo.
