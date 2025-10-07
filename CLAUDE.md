# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Simple IDM is an Identity Management system built with Go and SolidJS, providing authentication, authorization, and user management capabilities. It features OAuth2/OIDC support, 2FA, passwordless authentication, external provider integration, and a pluggable login flow architecture.

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
  - `loginv2/`: Main application server (OAuth2, OIDC, user management)
  - `oidc/`: Standalone OIDC provider
  - `login/`: Legacy login service
  - `passwordless-auth/`: Passwordless authentication service
  - `tokengen/`, `inituser/`, `emailtest/`, `mail/`: Utility commands

- **pkg/**: Core business logic organized by domain
  - Each package typically contains:
    - Service layer (`service.go`)
    - Database layer (`<package>db/`)
    - API handlers (`api/`)
    - Models and types

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

Key step execution orders:
- 100: Credential Authentication
- 200: User Validation
- 300: Login ID Parsing
- 400: Device Recognition
- 500: Two-Factor Authentication
- 600: Multiple User Selection
- 700: Token Generation
- 800: Success Recording

To create custom authentication flows, implement `LoginFlowStep` interface and use `FlowBuilder`.

#### 4. Service Dependencies
Services are initialized in `cmd/loginv2/main.go` with dependency injection:
1. Database connections established via `db-utils`
2. Service instances created with database queries
3. API handlers wired to services
4. Routes registered with chi router

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

## Configuration

### Environment Variables

Configuration is loaded from `.env` files in service directories (e.g., `cmd/loginv2/.env`):

Key variables:
- `IDM_PG_*`: Database connection settings
- `JWT_SECRET`: JWT signing secret
- `ACCESS_TOKEN_EXPIRY`, `REFRESH_TOKEN_EXPIRY`: Token lifetimes
- `EMAIL_*`: SMTP server configuration
- `BASE_URL`: Application base URL
- `COOKIE_HTTP_ONLY`, `COOKIE_SECURE`: Cookie security settings

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
- `/.well-known/*`: OIDC discovery and JWKS

## Important Notes

### First-Time Setup
When starting the server without existing users, an admin user is auto-created with credentials displayed in console output. **This only appears once** - save the credentials immediately.

### JWT Token Management
- Access tokens: Short-lived (default 5m)
- Refresh tokens: Medium-lived (default 15m)
- Temp tokens: Used for multi-step authentication flows (default 10m)
- Private keys stored in `auth/` directory

### Code Generation Workflow
When modifying database queries or API specs:
1. Edit SQL in `<package>db/query.sql` or OpenAPI YAML
2. Run code generation command
3. Update handler implementations if needed
4. Run tests to verify changes

### External Provider Integration
Supported providers configured via environment variables with prefix `<PROVIDER>_CLIENT_ID` and `<PROVIDER>_CLIENT_SECRET`. See `doc/EXTERNAL_PROVIDER_INTEGRATION.md`.
