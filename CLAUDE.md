# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Backend Development
```bash
# Build all Go binaries
make all

# Run backend with hot reload
make run

# Database operations
make migration-up          # Apply migrations
make migration-down        # Rollback migrations
make migration-create name="migration-name"  # Create new migration
make dump-idm             # Dump schema only
make dump-db              # Full database dump

# Update Go dependencies
make dep
```

### Frontend Development
```bash
cd frontend
npm install               # Install dependencies
npm run dev              # Start dev server (port 3000)
npm run build            # Production build
npx playwright test      # Run E2E tests
npx playwright test --ui # Run E2E tests with UI
```

### Full Stack Development
```bash
# Start everything with Docker Compose
docker-compose up --build

# Clean up containers and volumes
docker-compose down -v
```

## Architecture Overview

Simple-IDM is a modular identity management system built with:
- **Backend**: Go with Chi router, PostgreSQL, JWT authentication, and sqlc for type-safe queries
- **Frontend**: SolidJS with Vite, Tailwind CSS v4, and custom UI components
- **Infrastructure**: Docker Compose, Goose migrations, Mailpit for email testing

### Core Domains

The system follows domain-driven design with these key domains:
- **login**: Authentication, JWT tokens, session management
- **iam**: User identity and access management
- **role**: RBAC role management
- **profile**: User profile operations
- **twofa**: Two-factor authentication with TOTP
- **device**: Device recognition and fingerprinting
- **notification**: Email/SMS notifications via Mailpit and Twilio
- **signup**: User registration flows

### Key Architectural Patterns

1. **Database Access**: Uses sqlc to generate type-safe Go code from SQL queries. Query files are in `pkg/domain/*/repository/*.sql`
2. **API Generation**: OpenAPI specs in `api/` generate handlers using goapi-gen
3. **Configuration**: Environment-based config loaded via cleanenv in `pkg/config/`
4. **Authentication Flow**: JWT tokens (access, refresh, temp) with configurable expiration
5. **Security**: Argon2 password hashing, password policies, account lockout, device fingerprinting

### Testing Approach

- Backend: Standard Go testing (no specific test runner configured)
- Frontend: Playwright for E2E tests
- Development email testing via Mailpit at http://localhost:8025

### Important Files

- `config.yml.example`: Example configuration with all available options
- `pkg/domain/*/service.go`: Business logic for each domain
- `pkg/domain/*/repository/*.sql`: Database queries (sqlc source)
- `frontend/src/routes/`: SolidJS route components
- `api/*.yaml`: OpenAPI specifications