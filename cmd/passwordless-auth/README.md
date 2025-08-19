# Passwordless Auth Server

This is a simplified version of the simple-idm authentication server that focuses on passwordless authentication methods.

## Included Features

### Authentication Methods
- **Magic Link Login by Email**: `POST /api/idm/auth/login/magic-link/email`
- **Magic Link Validation**: `GET /api/idm/auth/login/magic-link/validate`
- **Passwordless Signup**: `POST /api/idm/signup/passwordless`
- **External OAuth Providers**: All `/api/idm/external/*` routes
  - Google OAuth2
  - Microsoft OAuth2
  - GitHub OAuth2
  - LinkedIn OAuth2

### 2FA Support (for Magic Link Flow)
- **Send 2FA Code**: `POST /api/idm/auth/2fa/send`
- **Validate 2FA Code**: `POST /api/idm/auth/2fa/validate`

### Protected Routes
- **Token Refresh**: `POST /api/idm/auth/token/refresh` (requires refresh token cookie)

### Device Management
- **List User Devices**: `GET /api/idm/device` (requires JWT authentication)
- **Delete Device**: `DELETE /api/idm/device/{deviceId}` (requires JWT authentication)
- **Update Device**: `PUT /api/idm/device/{deviceId}` (requires JWT authentication)

## Removed Features

This minimal version removes the following features from the full simple-idm server:
- Traditional username/password login
- User profile management
- User administration (IAM)
- Role management
- Login management
- Password reset functionality
- Email verification
- User switching
- OIDC OAuth2 server functionality

## Configuration

The server uses the same environment variables as the full simple-idm server. Key configuration includes:

### Database
- `IDM_PG_HOST` (default: localhost)
- `IDM_PG_PORT` (default: 5432)
- `IDM_PG_DATABASE` (default: idm_db)
- `IDM_PG_USER` (default: idm)
- `IDM_PG_PASSWORD` (default: pwd)

### JWT
- `JWT_SECRET` (default: very-secure-jwt-secret)
- `COOKIE_HTTP_ONLY` (default: true)
- `COOKIE_SECURE` (default: false)
- `ACCESS_TOKEN_EXPIRY` (default: 5m)
- `REFRESH_TOKEN_EXPIRY` (default: 15m)
- `TEMP_TOKEN_EXPIRY` (default: 10m)

### Email (for Magic Links)
- `EMAIL_HOST` (default: localhost)
- `EMAIL_PORT` (default: 1025)
- `EMAIL_USERNAME` (default: noreply@example.com)
- `EMAIL_PASSWORD` (default: pwd)
- `EMAIL_FROM` (default: noreply@example.com)
- `EMAIL_TLS` (default: false)

### Registration
- `LOGIN_REGISTRATION_ENABLED` (default: false)
- `LOGIN_REGISTRATION_DEFAULT_ROLE` (default: readonlyuser)

### Magic Link
- `MAGIC_LINK_TOKEN_EXPIRATION` (default: PT6H - 6 hours)

### External Providers
- `GOOGLE_ENABLED`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- `MICROSOFT_ENABLED`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`
- `GITHUB_ENABLED`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- `LINKEDIN_ENABLED`, `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET`
- `EXTERNAL_PROVIDER_DEFAULT_ROLE` (default: user)

## Usage

### Build and Run
```bash
cd simple-idm/cmd/passwordless-auth
go build
./passwordless-auth
```

### Example API Calls

#### Passwordless Signup
```bash
curl -X POST http://localhost:8080/api/idm/signup/passwordless \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "fullname": "John Doe"}'
```

#### Magic Link Login
```bash
curl -X POST http://localhost:8080/api/idm/auth/login/magic-link/email \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

#### Validate Magic Link
```bash
curl "http://localhost:8080/api/idm/auth/login/magic-link/validate?token=YOUR_TOKEN"
```

#### Refresh JWT Tokens
```bash
curl -X POST http://localhost:8080/token/refresh \
  -H "Cookie: refresh_token=YOUR_REFRESH_TOKEN_COOKIE"
```

## Architecture

This minimal server maintains the same core architecture as the full simple-idm server but with reduced functionality:

- **Database Layer**: PostgreSQL with SQLC-generated queries
- **Service Layer**: Domain services for login, signup, external providers
- **API Layer**: Chi router with specific endpoint handlers
- **Authentication**: JWT-based with cookie support
- **Notifications**: Email and SMS support for magic links and 2FA

The server is designed to be a lightweight authentication service focused on modern, passwordless authentication methods.
