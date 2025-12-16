# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Simple IDM is an Identity Management system built with Go and SolidJS, providing authentication, authorization, and user management capabilities. It features OAuth2/OIDC support, 2FA, passwordless authentication, external provider integration, email verification, and a pluggable login flow architecture.

**Main Service**: `cmd/loginv2/` is the primary production application combining all IDM functionality. Other services in `cmd/` are either legacy or utility tools.

## Development Commands

### Building
```bash
# Build all services (creates binaries in dist/)
make all

# Build specific service (e.g., loginv2)
GOARCH=amd64 GOOS=linux go build -buildvcs -o dist/loginv2 cmd/loginv2/main.go

# Clean build artifacts
make clean
```

### Testing
```bash
# Run all tests
go test -v ./...

# Run tests for a specific package
go test -v ./pkg/login/...

# Run a single test
go test -v ./pkg/login/... -run TestSpecificFunction
```

### Database Management
```bash
# Run database migrations
make migration-up

# Create a new migration
make migration-create name="migration-name"

# Rollback migration
make migration-down

# Dump database schema
make dump-idm

# Dump full database
make dump-db
```

### Code Generation
```bash
# Generate database query code (run from package directory)
cd pkg/<package_name> && sqlc generate

# Generate OpenAPI server code (run from api directory)
cd pkg/<package_name>/api && ./gen-<package>.sh
```

### Running Services

#### Development Mode
```bash
# Run main service with auto-reload
make run

# Run loginv2 service (main application)
cd cmd/loginv2 && go run main.go

# Start development mail server (Mailpit)
docker/start-mailpit.sh
# View emails at http://localhost:8025
```

#### Docker Compose (Quick Start)
```bash
# Start all services
docker-compose up --build

# Stop and clean up
docker-compose down -v
```

### Frontend Development
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Architecture

### Service Layer Structure

The codebase follows a domain-driven design with clear separation of concerns:

- **cmd/**: Executable entry points for different services

  **Production Services:**
  - `loginv2/`: **Main production application** - Full-featured IDM server with OAuth2, OIDC, 2FA, external providers, and all features. Uses `pkg/login/loginapi/` (v1 API with LoginFlowService).
  - `quick/`: **Simplified quick-start** - Minimal IDM server using v2 API handlers (`pkg/login/handler/v2/`). Good reference for new integrations.

  **Legacy Services (avoid for new projects):**
  - `login/`: Legacy login service using old `pkg/login/api/` package (direct service calls, no LoginFlowService)
  - `passwordless-auth/`: Standalone passwordless authentication service

  **Utility Commands:**
  - `tokengen/`: JWT token generation utility
  - `inituser/`: Initialize user accounts
  - `emailtest/`: Test email configuration
  - `mail/`: Mail-related utilities

  **Examples/Testing:**
  - `oidc-client/`: OIDC client example
  - `oidc-server/`: OIDC server example

- **pkg/**: Core business logic organized by domain
  - Each package typically contains:
    - Service layer (`service.go`)
    - Database layer (`<package>db/`)
    - API handlers (`api/`)
    - Models and types

### Login Package Structure

The login package has multiple API implementations for different use cases:

| Package | Used By | Description |
|---------|---------|-------------|
| `pkg/login/loginapi/` | `cmd/loginv2/`, `pkg/router/` | **Current v1 API** - Uses `LoginFlowService` for orchestrated auth flows |
| `pkg/login/handler/v2/` | `cmd/quick/` | **v2 API** - Simplified handlers, cleaner interface |
| `pkg/login/api/` | `cmd/login/` (legacy) | **Legacy API** - Direct service calls, avoid for new code |

**Recommendation**: Use `pkg/router/` helpers with `MinimalOptions` for easy integration, which internally uses the current v1 API.

### Repository Pattern

Most packages support multiple storage backends via the repository pattern:

| Type | Use Case | Example |
|------|----------|---------|
| `Postgres*Repository` | **Production** - PostgreSQL database | `NewPostgresLoginRepository()` |
| `InMemory*Repository` | **Development/Testing** - No persistence | `NewInMemoryOIDCRepository()` |
| `File*Repository` | **Simple deployments** - JSON file storage | `NewFileDeviceRepository()` |
| `NoOp*Repository` | **Disabled features** - No-op implementations | `NewNoOpDeviceRepository()` |

Factory functions (e.g., `NewDeviceRepository(persistenceType, config)`) allow runtime selection of storage backend.

### Key Architectural Patterns

#### 1. Database Access with sqlc
Database queries are defined in SQL and code is generated using sqlc:
- SQL queries: `pkg/<package>/<package>db/query.sql`
- Generated code: `pkg/<package>/<package>db/query.sql.go`
- Configuration: `pkg/<package>/sqlc.yaml`
- Schema: `migrations/idm_db.sql`

To regenerate database code after modifying queries:
```bash
cd pkg/<package> && sqlc generate
```

#### 2. OpenAPI-Generated HTTP Handlers
API routes are defined in OpenAPI YAML specs and server code is generated:
- OpenAPI spec: `pkg/<package>/api/<package>.yaml`
- Generated server: `pkg/<package>/api/<package>.gen.go`
- Custom handlers: `pkg/<package>/api/handle.go`

To regenerate API code:
```bash
cd pkg/<package>/api && ./<gen-script>.sh
```

#### 3. Pluggable Login Flow System
The `pkg/loginflow/` package implements a sophisticated, modular authentication flow:
- **Steps**: Individual authentication actions (credential validation, 2FA, device recognition)
- **Registry**: Manages and orders steps by priority
- **Executor**: Orchestrates step execution
- **FlowContext**: Carries state between steps
- **Pre-configured Flows**: Web, mobile, email, magic link, passwordless

Key step execution orders (see `pkg/loginflow/flow.go`):
- 50: Temp Token Validation (for resumption flows)
- 100: Credential Authentication
- 200: User Validation
- 400: Device Recognition
- 500: Two-Factor Authentication Requirement Check
- 550: Two-Factor Authentication Validation (resumption)
- 560: User Switch Validation (resumption)
- 570: User Lookup (resumption)
- 575: Device Remembering
- 580: Two-Factor Send
- 600: Multiple User Selection
- 700: Token Generation
- 800: Success Recording

To create custom authentication flows, implement `LoginFlowStep` interface and use `FlowBuilder`. Steps can be skipped based on context (e.g., 2FA skipped if device recognized).

#### 4. Service Dependencies
Services are initialized in `cmd/loginv2/main.go` with dependency injection:
1. Database connections established via `db-utils`
2. Service instances created with database queries
3. API handlers wired to services
4. Routes registered with chi router

#### 5. Authentication Middleware
The application uses a layered middleware approach for route protection:
- **Public routes**: No authentication required (login, signup, email verification, external auth, well-known endpoints)
- **Protected routes**: Use `jwtauth.Verifier` + `jwtauth.Authenticator` + `client.AuthUserMiddleware`
  - `MultiAlgorithmVerifier`: Supports both RSA-256 (primary) and HMAC-256 (fallback)
  - `AuthUserMiddleware`: Extracts user info into `client.AuthUser` context value
- **Admin routes**: Additional `client.AdminRoleMiddleware` for role-based access control
- Token verification: RSA public key validation using JWKS

### Core Domains

- **iam**: User and group management, role assignment
- **auth**: Authentication and JWT token management
- **login**: Password-based authentication, password hashing (bcrypt/argon2)
- **logins**: Login session tracking and management
- **twofa**: Two-factor authentication (TOTP)
- **oauth2client**: OAuth2 client management and authorization flows
- **oidc**: OpenID Connect provider implementation
- **device**: Device fingerprinting and recognition
- **externalprovider**: Integration with external OAuth providers (Google, GitHub, etc.)
- **jwks**: JSON Web Key Set management for token signing
- **notification**: Email/SMS notifications via Twilio and SMTP
- **profile**: User profile management
- **role**: Role-based access control
- **signup**: User registration and invitation codes
- **mapper**: User-to-login mapping for multiple accounts
- **delegate**: Delegation and impersonation
- **emailverification**: Email verification with token-based validation
- **wellknown**: OAuth2/OIDC well-known endpoints for MCP compliance

### Database

- **PostgreSQL** with pgx driver
- **Migrations**: Managed by goose in `migrations/idm/`
- **Schema**: `migrations/idm_db.sql`
- **Connection**: Configured via environment variables (`IDM_PG_*`)

Default connection:
```
Host: localhost:5432
Database: idm_db
User: idm
Password: pwd
```

## Quick Integration

For projects that want to add authentication quickly, use the `pkg/router` helpers:

```go
package main

import (
    "log"
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/tendant/simple-idm/pkg/router"
)

func main() {
    // Create minimal configuration
    cfg, err := router.NewMinimalConfig(router.MinimalOptions{
        DatabaseURL: "postgres://user:pwd@localhost:5432/mydb?sslmode=disable",
        JWTSecret:   "your-secure-secret",
        BaseURL:     "http://localhost:8000",

        // Optional: Enable Google OAuth
        GoogleClientID:     "your-google-client-id",
        GoogleClientSecret: "your-google-client-secret",
    })
    if err != nil {
        log.Fatal(err)
    }

    r := chi.NewRouter()
    router.SetupRoutes(r, cfg)  // Mounts all IDM routes

    http.ListenAndServe(":8000", r)
}
```

This gives you:
- Login/logout/refresh endpoints (`/api/idm/auth/*`)
- User registration (`/api/idm/signup/*`)
- OAuth2/OIDC provider (`/api/idm/oauth2/*`)
- External provider auth (`/api/idm/external/*`) if configured
- Protected routes with JWT middleware
- Admin routes for user/role management

## Configuration

### Environment Variables

Configuration is loaded from `.env` files in service directories (e.g., `cmd/loginv2/.env`):

Key variables:
- `IDM_PG_*`: Database connection settings
- `JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`: JWT configuration
- `ACCESS_TOKEN_EXPIRY`, `REFRESH_TOKEN_EXPIRY`, `TEMP_TOKEN_EXPIRY`: Token lifetimes (ISO 8601 duration format)
- `EMAIL_*`: SMTP server configuration
- `BASE_URL`: Application base URL (backend)
- `FRONTEND_URL`: Frontend application URL (for redirects and email links)
- `COOKIE_HTTP_ONLY`, `COOKIE_SECURE`: Cookie security settings
- `JWKS_PRIVATE_KEY_FILE`, `JWKS_KEY_ID`, `JWKS_ALGORITHM`: RSA key configuration for token signing
- `PASSWORD_COMPLEXITY_*`: Password policy settings
- `LOGIN_*`: Login behavior (max attempts, lockout, registration, magic link expiration)
- `OAUTH2_CLIENT_ENCRYPTION_KEY`: OAuth2 client secret encryption (32 bytes base64)
- `<PROVIDER>_CLIENT_ID`, `<PROVIDER>_CLIENT_SECRET`, `<PROVIDER>_ENABLED`: External OAuth provider configuration

Refer to `cmd/loginv2/.env.example` for complete list.

## Testing

Tests use:
- **testify** for assertions
- **testcontainers-go** for integration tests with PostgreSQL

Common patterns:
- Service layer tests: `pkg/<package>/service_test.go`
- Repository tests: `pkg/<package>/<package>db/repository_test.go`
- Mock implementations for external dependencies

## API Endpoints

The main application exposes APIs at http://localhost:4000:

- `/api/idm/auth/*`: Authentication (login, logout, token refresh)
- `/api/idm/profile/*`: User profile management
- `/api/idm/device/*`: Device management
- `/idm/2fa/*`: Two-factor authentication
- `/idm/users/*`: User management (admin)
- `/idm/roles/*`: Role management (admin)
- `/api/idm/logins/*`: Login session management
- `/api/idm/signup/*`: User registration
- `/api/idm/email/*`: Email verification (verify public, resend/status require auth)
- `/api/idm/oauth2/*`: OAuth2/OIDC endpoints
- `/api/idm/external/*`: External provider authentication
- `/api/idm/oauth2-clients/*`: OAuth2 client management (admin only)
- `/.well-known/*`: OIDC discovery, authorization server metadata, and JWKS

## Important Notes

### First-Time Setup
When starting the server without existing users, an admin user is auto-created with credentials displayed in console output. **This only appears once** - save the credentials immediately.

### JWT Token Management
- Access tokens: Short-lived (default 5m)
- Refresh tokens: Medium-lived (default 15m)
- Temp tokens: Used for multi-step authentication flows (default 10m)
- Logout tokens: Immediate expiry (default -1m)
- RSA keys: Generated private key stored as `jwt-private.pem` (configurable via `JWKS_PRIVATE_KEY_FILE`)
- Token signing: Uses RSA-256 algorithm with JWKS support
- Multi-algorithm support: Both RSA-256 (primary) and HMAC-256 (fallback) verification

### Device Recognition and "Remember Me"
The device recognition system allows users to skip 2FA on trusted devices:
- **Device Fingerprinting**: Client-side fingerprints are sent with login requests
- **Device Linking**: After successful 2FA, devices can be "remembered" (linked to login)
- **Expiration**: Device links expire after a configurable period (default 90 days, set via `DEVICE_EXPIRATION_DAYS`)
- **Automatic Skip**: Recognized, non-expired devices skip 2FA requirement
- **Last Login Tracking**: Device last login times are updated on each successful authentication

Flow:
1. User logs in with credentials
2. Device fingerprint checked against stored devices
3. If recognized and not expired → skip 2FA
4. If not recognized → require 2FA
5. After 2FA success with "remember device" flag → link device to login

### Code Generation Workflow
When modifying database queries or API specs:
1. Edit SQL in `<package>db/query.sql` or OpenAPI YAML
2. Run code generation command
3. Update handler implementations if needed
4. Run tests to verify changes

### Password Management
- Supports both **bcrypt** and **argon2** hashing algorithms
- Password policy enforcement with configurable complexity requirements
- Password history tracking to prevent reuse
- Password expiration support with configurable periods
- Common password dictionary checking (when enabled)

### Notification System
The `pkg/notice/` package provides a unified notification manager that supports:
- **Email**: Via SMTP (configured with `EMAIL_*` environment variables)
- **SMS**: Via Twilio (configured with `TWILIO_*` environment variables)
- **Templates**: Pre-built templates for common notifications (email verification, 2FA codes, password reset, etc.)

Used by:
- Email verification flows
- Two-factor authentication
- Password reset
- Magic link authentication
- External provider notifications

### Signup Service Migration

The signup package has two option patterns:

**Legacy (Handle-level options)** - Still used in production but deprecated:
```go
// Old pattern - deprecated
signup.NewHandleWithOptions(
    signup.WithIamService(*iamService),
    signup.WithRoleService(*roleService),
    signup.WithLoginsService(*loginsService),
)
```

**New (Service-level options)** - Recommended for new code:
```go
// New pattern - recommended
signupService := signup.NewSignupService(
    signup.WithIamServiceForSignup(iamService),
    signup.WithRoleServiceForSignup(roleService),
    signup.WithLoginsServiceForSignup(loginsService),
)
signupHandle := signup.NewHandle(signupService)
```

See `cmd/quick/main.go` for a complete example of the new pattern.

### External Provider Integration
Supported providers configured via environment variables with prefix `<PROVIDER>_CLIENT_ID` and `<PROVIDER>_CLIENT_SECRET`. See `doc/EXTERNAL_PROVIDER_INTEGRATION.md`.

Providers:
- Google OAuth2
- Microsoft OAuth2
- GitHub OAuth2
- LinkedIn OAuth2

Features:
- Auto user creation (configurable)
- Default role assignment for new users
- State management for OAuth flows
- User info mapping to internal user model
