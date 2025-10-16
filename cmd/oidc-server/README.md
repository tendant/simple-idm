# OIDC Server Demo

A standalone OpenID Connect (OIDC) / OAuth2 Provider demonstration server built with Go.

## Features

- **Complete OIDC/OAuth2 Provider** implementation
- **Authorization Code Flow** with PKCE support
- **JWT Token Generation** using RSA-256 algorithm
- **OIDC Discovery** endpoints (`.well-known/openid-configuration`)
- **JWKS endpoint** for public key distribution
- **Pure HTML** web interface for login and consent
- **RESTful API** endpoints under `/api` prefix
- **In-memory storage** for demo purposes (users, clients, sessions)

## Quick Start

### 1. Build and Run

```bash
# From the project root
cd cmd/oidc-server
go run main.go
```

The server will start on `http://localhost:4001`

### 2. Access the Server

Open your browser and navigate to:
- **Home Page**: http://localhost:4001
- **OIDC Discovery**: http://localhost:4001/.well-known/openid-configuration
- **JWKS Endpoint**: http://localhost:4001/jwks

## Configuration

### Pre-configured Demo Client

The server comes with a pre-configured OAuth2 client:

```
Client ID:       demo-client
Client Secret:   demo-secret
Redirect URIs:   http://localhost:4002/callback
                 http://localhost:5173/callback
Grant Types:     authorization_code, refresh_token
Scopes:          openid, profile, email, groups
```

### Demo Users

Two demo users are available for testing:

| Username | Password | Email              | Name          |
|----------|----------|--------------------|---------------|
| demo     | password | demo@example.com   | Demo User     |
| alice    | password | alice@example.com  | Alice Johnson |

## API Endpoints

### Authorization Endpoint
```
GET /api/oidc/authorize
```

**Parameters:**
- `response_type`: `code` (required)
- `client_id`: OAuth2 client ID (required)
- `redirect_uri`: Callback URL (required)
- `scope`: Space-separated scopes (e.g., `openid profile email`)
- `state`: CSRF protection token (recommended)
- `code_challenge`: PKCE code challenge (optional)
- `code_challenge_method`: `S256` or `plain` (optional)

**Response:**
- Redirects to login page if user not authenticated
- Redirects to `redirect_uri` with authorization code on success

### Token Endpoint
```
POST /api/oidc/token
```

**Parameters (form-encoded):**
- `grant_type`: `authorization_code` (required)
- `code`: Authorization code from authorize endpoint (required)
- `redirect_uri`: Must match the original redirect_uri (required)
- `client_id`: OAuth2 client ID (required)
- `client_secret`: OAuth2 client secret (required)
- `code_verifier`: PKCE code verifier (if PKCE used)

**Response (JSON):**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGc...",
  "scope": "openid profile email"
}
```

### UserInfo Endpoint
```
GET /api/oidc/userinfo
Authorization: Bearer <access_token>
```

**Response (JSON):**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Demo User",
  "email": "demo@example.com",
  "groups": ["users", "demo"]
}
```

## Web Pages

### Home Page
```
GET /
```
Displays server information, configuration, and available endpoints.

### Login Page
```
GET /login?redirect=<return_url>
POST /login
```
Simple username/password login form. Users are redirected back to the `redirect` parameter after successful authentication.

## Discovery Endpoints

### OpenID Configuration
```
GET /.well-known/openid-configuration
```
Returns OIDC discovery metadata including all endpoint URLs and supported features.

### OAuth Authorization Server Metadata
```
GET /.well-known/oauth-authorization-server
```
Returns OAuth2 authorization server metadata (RFC 8414).

### JWKS (JSON Web Key Set)
```
GET /jwks
```
Returns public keys for JWT token verification.

## Authentication Flow Example

### 1. Client initiates authorization
```
GET /api/oidc/authorize?
  response_type=code&
  client_id=demo-client&
  redirect_uri=http://localhost:4002/callback&
  scope=openid%20profile%20email&
  state=xyz123
```

### 2. User logs in
Server redirects to `/login` if not authenticated. User submits credentials.

### 3. Authorization code issued
Server redirects to client's redirect_uri:
```
http://localhost:4002/callback?code=abc123&state=xyz123
```

### 4. Client exchanges code for tokens
```bash
curl -X POST http://localhost:4001/api/oidc/token \
  -d "grant_type=authorization_code" \
  -d "code=abc123" \
  -d "redirect_uri=http://localhost:4002/callback" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-secret"
```

### 5. Client accesses user info
```bash
curl http://localhost:4001/api/oidc/userinfo \
  -H "Authorization: Bearer <access_token>"
```

## Security Features

- **CSRF Protection**: State parameter validation
- **PKCE Support**: Proof Key for Code Exchange (RFC 7636)
- **JWT Signatures**: RSA-256 signed tokens
- **HTTP-only Cookies**: Session cookies not accessible to JavaScript
- **Short-lived Codes**: Authorization codes expire in 10 minutes
- **Token Expiration**: Access tokens expire in 1 hour

## Architecture

The server uses the existing `simple-idm` packages:

- `pkg/oidc`: Core OIDC service logic
- `pkg/oauth2client`: OAuth2 client management
- `pkg/tokengenerator`: JWT token generation
- `pkg/jwks`: JWKS key management
- `pkg/wellknown`: Discovery endpoint handlers

## Development Notes

### In-Memory Storage

This demo uses in-memory storage for:
- Users
- OAuth2 clients
- Sessions
- Authorization codes

**Warning**: All data is lost when the server restarts. For production use, implement persistent storage.

### Token Generation

Tokens are signed using RSA-256 with a dynamically generated key pair. The public key is available via the JWKS endpoint.

### Session Management

Sessions are stored in memory with 1-hour expiration. Session cookies are HTTP-only for security.

## Testing with OIDC Client

A companion client application is available at `cmd/oidc-client`:

```bash
# Terminal 1: Start OIDC Server
cd cmd/oidc-server
go run main.go

# Terminal 2: Start OIDC Client
cd cmd/oidc-client
go run main.go

# Open browser
open http://localhost:4002
```

## Troubleshooting

### "Invalid client credentials"
- Verify client_id is `demo-client`
- Verify client_secret is `demo-secret`

### "Redirect URI mismatch"
- Ensure redirect_uri matches exactly: `http://localhost:4002/callback`
- Check for trailing slashes and protocol (http vs https)

### "Invalid authorization code"
- Authorization codes expire in 10 minutes
- Codes can only be used once
- Verify the code wasn't already exchanged

### "Invalid access token"
- Access tokens expire in 1 hour
- Verify Bearer token format: `Authorization: Bearer <token>`

## Reference Documentation

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Discovery RFC 8414](https://tools.ietf.org/html/rfc8414)
