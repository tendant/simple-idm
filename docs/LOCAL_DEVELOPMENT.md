# Local Development Guide

This guide covers how to test Simple IDM APIs locally without complex setup.

## Quick API Testing (No Database Required)

### Option 1: In-Memory Mode (Fastest)

Start the in-memory server - no database, no configuration needed:

```bash
cd cmd/inmem
go run main.go
```

**Ready to use:**
- Server: `http://localhost:4000`
- Login: `admin@example.com` / `password123`
- All data stored in memory (lost on restart)

**Test it:**
```bash
# Login and get token
curl -X POST http://localhost:4000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"password123"}'

# Use token for authenticated requests
TOKEN="<token from response>"
curl http://localhost:4000/api/idm/users \
  -H "Authorization: Bearer $TOKEN"
```

**Available Endpoints:**
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v2/auth/login` | POST | No | Login |
| `/api/v2/auth/logout` | POST | No | Logout |
| `/api/v2/auth/refresh` | POST | No | Refresh token |
| `/api/v2/auth/signup` | POST | No | Register user |
| `/api/idm/users` | GET | Yes | List users |
| `/api/idm/roles` | GET | Yes | List roles |
| `/health` | GET | No | Health check |

---

### Option 2: Token Generator

Generate test JWT tokens without running any server:

```bash
# Basic token
go run cmd/tokengen/main.go

# Token with your app's secret
go run cmd/tokengen/main.go -secret "your-jwt-secret"

# Token with custom claims
go run cmd/tokengen/main.go \
  -secret "your-jwt-secret" \
  -subject "user-123" \
  -expiry 1h \
  -claims '{"user_uuid":"550e8400-e29b-41d4-a716-446655440000","roles":["admin"],"email":"test@example.com"}'

# Debug output (shows header + claims)
go run cmd/tokengen/main.go -format debug
```

**Options:**
| Flag | Default | Description |
|------|---------|-------------|
| `-secret` | `your-secret-key` | JWT signing secret |
| `-issuer` | `simple-idm` | Token issuer |
| `-audience` | `public` | Token audience |
| `-subject` | `test-subject` | Subject (user ID) |
| `-expiry` | `30m` | Token lifetime |
| `-claims` | `{}` | Extra claims (JSON) |
| `-format` | `compact` | Output: compact/full/debug |

**One-liner for curl:**
```bash
TOKEN=$(go run cmd/tokengen/main.go -secret "your-secret")
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/protected
```

---

### Option 3: Quick Service (Simplified Production-Like)

For a more complete setup with OIDC support:

```bash
# 1. Start PostgreSQL
podman run -d --name idm-postgres \
  -e POSTGRES_PASSWORD=pwd \
  -e POSTGRES_USER=idm \
  -e POSTGRES_DB=idm_db \
  -p 5432:5432 \
  postgres:17-alpine

# 2. Run migrations
make migration-up

# 3. Start service
cd cmd/quick
cp .env.example .env
go run main.go
```

**Features:**
- OIDC provider with auto-generated RSA keys
- Admin user auto-created (credentials shown once on first run)
- Magic link authentication
- Data persisted in PostgreSQL

---

## Using simple-idm as a Library

When integrating simple-idm into your own application, use these patterns for testing:

### Pattern 1: Token Generator for Manual Testing

```bash
# Generate token matching your app's JWT configuration
TOKEN=$(go run github.com/tendant/simple-idm/cmd/tokengen \
  -secret "your-app-jwt-secret" \
  -claims '{"user_uuid":"test-uuid","roles":["user"]}')

# Test your protected endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/your-endpoint
```

### Pattern 2: In-Memory Repositories for Integration Tests

```go
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/jwtauth/v5"
    "github.com/tendant/simple-idm/pkg/client"
    "github.com/tendant/simple-idm/pkg/login"
    "github.com/tendant/simple-idm/pkg/iam"
)

func main() {
    r := chi.NewRouter()

    // Use in-memory repos (no database needed)
    loginRepo := login.NewInMemoryLoginRepository()
    iamRepo := iam.NewInMemoryIamRepository()

    // Create JWT auth
    jwtSecret := "dev-secret"
    jwtAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)

    // Seed test user
    loginRepo.SeedLogin(login.LoginEntity{
        ID:       uuid.New(),
        Username: "test@example.com",
        Password: hashPassword("password123"),
    }, "test@example.com")

    // Protected routes
    r.Group(func(r chi.Router) {
        r.Use(client.AuthMiddleware(
            client.VerifierConfig{Name: "HMAC", Auth: jwtAuth, Active: true},
        ))
        r.Use(client.RequireAuth)

        r.Get("/api/protected", myHandler)
    })

    http.ListenAndServe(":8000", r)
}
```

### Pattern 3: Dev Bypass Middleware (Testing Only)

```go
// DevAuthMiddleware bypasses auth and injects a test user
func DevAuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        testUser := &client.AuthUser{
            UserUuid: uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
            Email:    "dev@example.com",
            Roles:    []string{"admin"},
        }
        ctx := context.WithValue(r.Context(), client.AuthUserKey, testUser)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Usage - toggle based on environment
func setupRoutes(r chi.Router, isDev bool) {
    r.Group(func(r chi.Router) {
        if isDev {
            r.Use(DevAuthMiddleware)
        } else {
            r.Use(client.AuthMiddleware(...))
            r.Use(client.RequireAuth)
        }
        r.Get("/api/protected", handler)
    })
}
```

### Pattern 4: Test Helper Function

```go
// test_helpers.go
func GenerateTestToken(userID uuid.UUID, roles []string) string {
    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        jwtSecret = "test-secret"
    }

    tokenGen := tokengenerator.NewJwtTokenGenerator(jwtSecret, "test", "test")
    token, _, _ := tokenGen.GenerateToken(userID.String(), 15*time.Minute, nil, map[string]interface{}{
        "user_uuid": userID.String(),
        "roles":     roles,
        "email":     "test@example.com",
    })

    return token
}

// In tests
func TestMyAPI(t *testing.T) {
    token := GenerateTestToken(uuid.New(), []string{"user"})

    req := httptest.NewRequest("GET", "/api/endpoint", nil)
    req.Header.Set("Authorization", "Bearer "+token)

    // ... run test
}
```

---

## Development Mail Server

For testing email functionality (magic links, verification, etc.):

```bash
# Start Mailpit
docker/start-mailpit.sh

# Or manually with podman/docker
podman run -d --name mailpit \
  -p 8025:8025 \
  -p 1025:1025 \
  axllent/mailpit
```

**Access:**
- Web UI: http://localhost:8025
- SMTP: localhost:1025

**Configure in .env:**
```bash
EMAIL_HOST=localhost
EMAIL_PORT=1025
EMAIL_FROM=noreply@example.com
EMAIL_TLS=false
```

---

## Quick Comparison

| Method | Database | Setup Time | Best For |
|--------|----------|------------|----------|
| In-Memory (`cmd/inmem`) | No | Instant | Quick API testing |
| Token Generator | No | Instant | Testing protected endpoints |
| Quick Service | Yes | ~2 min | Full OIDC testing |
| Dev Bypass Middleware | No | Code change | Fast local development |
| Test Helper | No | Code change | Automated tests |

---

## Troubleshooting

### Token not accepted
- Ensure the secret matches between token generator and your app
- Check token expiry with `-format debug`
- Verify the `Authorization: Bearer <token>` header format

### In-memory server won't start
- Check port 4000 is available
- Run from the correct directory (`cmd/inmem`)

### Database connection issues (Quick Service)
- Verify PostgreSQL is running: `pg_isready`
- Check connection settings in `.env`
- Run migrations: `make migration-up`
