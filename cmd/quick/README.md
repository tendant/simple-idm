# Quick IDM - Simplified Identity Management Service

A streamlined, production-ready identity management service with OAuth2/OIDC support, password authentication, and passwordless (magic link) login. Perfect for quickly adding authentication to your applications.

## Features

- **Password Authentication**: Traditional username/password login
- **Passwordless Authentication**: Magic link login via email
- **OIDC Provider**: Full OAuth2/OpenID Connect server for SSO
- **Auto-Configuration**: RSA keys auto-generated on first run
- **Minimal Setup**: Just database + email server required
- **Production Ready**: Uses RSA-256 JWT tokens, proper PKCE support

## Quick Start

### 1. Prerequisites

- PostgreSQL database
- Go 1.21+ (for running from source)
- Email server (use Mailpit for local dev)

### 2. Setup Database

```bash
# Create database
createdb idm_db

# Run migrations (from project root)
make migration-up
```

### 3. Configure Service

```bash
cd cmd/quick

# Copy example config
cp .env.example .env

# Edit .env with your settings (minimal required):
# - Database connection
# - Email server settings
```

### 4. Start Development Email Server (Optional)

```bash
# From project root
docker/start-mailpit.sh

# View emails at http://localhost:8025
```

### 5. Run Service

```bash
go run main.go
```

On first run:
- RSA key pair is auto-generated (`jwt-private.pem`)
- Admin user is created (credentials shown once - **save them!**)
- OIDC provider is ready at `http://localhost:4000`

### 6. Test It Works

```bash
# Check OIDC discovery
curl http://localhost:4000/.well-known/openid-configuration

# Check JWKS (public keys)
curl http://localhost:4000/.well-known/jwks.json
```

## Authentication Methods

### Password Login

```bash
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-admin-password"
  }'
```

Response includes `access_token` and `refresh_token`.

### Magic Link (Passwordless)

```bash
# 1. Request magic link
curl -X POST http://localhost:4000/api/auth/magic-link/email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'

# 2. User clicks link in email (or visit URL directly)
# http://localhost:4000/api/auth/magic-link/validate?token=...

# 3. Automatically logged in with tokens set
```

## User Registration

### Passwordless Signup

```bash
curl -X POST http://localhost:4000/api/signup/passwordless \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

User receives magic link to complete registration.

### Password Signup (if enabled)

```bash
curl -X POST http://localhost:4000/api/signup/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "secure-password",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

## Using as OIDC Provider

### 1. Create OAuth2 Client

Login as admin and create a client:

```bash
# Get admin token first
TOKEN=$(curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  | jq -r '.access_token')

# Create OAuth2 client
curl -X POST http://localhost:4000/api/oauth2-clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": ["openid", "profile", "email"]
  }'
```

Save the returned `client_id` and `client_secret`.

### 2. Configure Your Application

Use these OIDC endpoints in your app:

```
Issuer:            http://localhost:4000
Discovery:         http://localhost:4000/.well-known/openid-configuration
Authorization URL: http://localhost:4000/api/oauth2/authorize
Token URL:         http://localhost:4000/api/oauth2/token
UserInfo URL:      http://localhost:4000/api/oauth2/userinfo
JWKS URL:          http://localhost:4000/.well-known/jwks.json
```

### 3. Example: Node.js with Passport

```javascript
const passport = require('passport');
const OIDCStrategy = require('passport-openidconnect').Strategy;

passport.use('oidc', new OIDCStrategy({
  issuer: 'http://localhost:4000',
  authorizationURL: 'http://localhost:4000/api/oauth2/authorize',
  tokenURL: 'http://localhost:4000/api/oauth2/token',
  userInfoURL: 'http://localhost:4000/api/oauth2/userinfo',
  clientID: 'your-client-id',
  clientSecret: 'your-client-secret',
  callbackURL: 'http://localhost:3000/callback',
  scope: 'openid profile email'
}, (issuer, profile, done) => {
  return done(null, profile);
}));
```

### 4. Example: Python with Authlib

```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    name='quick-idm',
    client_id='your-client-id',
    client_secret='your-client-secret',
    server_metadata_url='http://localhost:4000/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email'
    }
)
```

## API Endpoints

### Public Endpoints (No Authentication)

**Authentication**:
- `POST /api/auth/login` - Password login
- `POST /api/auth/magic-link/email` - Request magic link
- `GET /api/auth/magic-link/validate?token=<token>` - Validate magic link
- `POST /api/auth/token/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout

**Registration**:
- `POST /api/signup/passwordless` - Register without password
- `POST /api/signup/register` - Register with password

**OAuth2/OIDC**:
- `GET /.well-known/openid-configuration` - OIDC discovery
- `GET /.well-known/oauth-authorization-server` - OAuth2 metadata
- `GET /.well-known/oauth-protected-resource` - Resource server metadata
- `GET /.well-known/jwks.json` - Public signing keys
- `GET /api/oauth2/authorize` - Authorization endpoint
- `POST /api/oauth2/token` - Token endpoint
- `GET /api/oauth2/userinfo` - UserInfo endpoint

### Protected Endpoints (Requires Authentication)

**User Info**:
- `GET /me` - Get current user information

**User Management**:
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{id}` - Get user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

**Role Management (Admin Only)**:
- `GET /api/roles` - List roles
- `POST /api/roles` - Create role
- `GET /api/roles/{id}` - Get role
- `PUT /api/roles/{id}` - Update role
- `DELETE /api/roles/{id}` - Delete role

**OAuth2 Client Management (Admin Only)**:
- `GET /api/oauth2-clients` - List OAuth2 clients
- `POST /api/oauth2-clients` - Create OAuth2 client
- `GET /api/oauth2-clients/{id}` - Get OAuth2 client
- `PUT /api/oauth2-clients/{id}` - Update OAuth2 client
- `DELETE /api/oauth2-clients/{id}` - Delete OAuth2 client

## Configuration Reference

### Required Environment Variables

```bash
# Application URLs
BASE_URL=http://localhost:4000          # Backend API base URL
FRONTEND_URL=http://localhost:3000      # Frontend app URL (for redirects)

# Database
IDM_PG_HOST=localhost
IDM_PG_PORT=5432
IDM_PG_DATABASE=idm_db
IDM_PG_USER=idm
IDM_PG_PASSWORD=pwd
IDM_PG_SCHEMA=public

# Email
EMAIL_HOST=localhost
EMAIL_PORT=1025
EMAIL_FROM=noreply@example.com
EMAIL_USERNAME=                         # Optional
EMAIL_PASSWORD=                         # Optional
EMAIL_TLS=false
```

### Optional Environment Variables

```bash
# JWT Configuration
JWT_KEY_FILE=jwt-private.pem            # Auto-generated if missing
JWT_ISSUER=quick-idm                    # JWT issuer claim
ACCESS_TOKEN_EXPIRY=15m                 # Access token lifetime
REFRESH_TOKEN_EXPIRY=24h                # Refresh token lifetime
TEMP_TOKEN_EXPIRY=10m                   # Temporary token lifetime

# Registration
REGISTRATION_ENABLED=true               # Allow public registration
REGISTRATION_DEFAULT_ROLE=user          # Default role for new users

# Magic Link
MAGIC_LINK_EXPIRATION=1h                # Magic link validity

# OAuth2
OAUTH2_CLIENT_ENCRYPTION_KEY=           # Auto-generated if not set

# Cookies
COOKIE_SECURE=false                     # Set true for HTTPS
COOKIE_HTTP_ONLY=true                   # HTTP-only cookies
```

## Production Deployment

### 1. Generate Secure Keys

```bash
# Generate OAuth2 encryption key
openssl rand -hex 32

# Add to .env
OAUTH2_CLIENT_ENCRYPTION_KEY=your-generated-key
```

### 2. Use HTTPS

```bash
# Update .env
BASE_URL=https://idm.yourdomain.com
COOKIE_SECURE=true
```

### 3. Configure Production Email

```bash
# Example: Gmail SMTP
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_FROM=noreply@yourdomain.com
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_TLS=true
```

### 4. Build and Deploy

```bash
# Build binary
GOOS=linux GOARCH=amd64 go build -o quick-idm main.go

# Deploy to server
scp quick-idm user@server:/opt/quick-idm/
scp .env user@server:/opt/quick-idm/

# Run as systemd service
sudo systemctl start quick-idm
```

### 5. Backup RSA Keys

The `jwt-private.pem` file contains your signing key. **Back it up securely!**

If you lose this key:
- All existing tokens become invalid
- Users must re-authenticate
- OIDC clients need to fetch new public keys

## Differences from `loginv2`

Quick IDM is a simplified version that removes:

- ❌ External OAuth providers (Google, GitHub, Microsoft, LinkedIn)
- ❌ Two-factor authentication (TOTP)
- ❌ Device recognition / "Remember me"
- ❌ Complex login flow system
- ❌ Email verification workflows
- ❌ SMS notifications (Twilio)
- ❌ Delegation/impersonation
- ❌ Strict password complexity policies
- ❌ Multi-algorithm JWT support

Quick IDM provides:

- ✅ Password + passwordless authentication
- ✅ Full OIDC provider capabilities
- ✅ Auto-generated RSA keys (zero setup)
- ✅ User and role management
- ✅ OAuth2 client management
- ✅ Production-ready security (RSA-256, PKCE)
- ✅ Minimal configuration

## Troubleshooting

### RSA Key Generation Failed

**Error**: `Failed to ensure RSA key`

**Solution**: Ensure the current directory is writable. The service generates `jwt-private.pem` on first run.

### Database Connection Failed

**Error**: `Failed to connect to database`

**Solution**:
1. Check PostgreSQL is running: `pg_isready`
2. Verify database exists: `psql -l | grep idm_db`
3. Check credentials in `.env`
4. Run migrations: `make migration-up`

### Email Not Sending

**Problem**: Magic links not arriving

**Solution**:
1. Check email server is running (Mailpit: http://localhost:8025)
2. Verify `EMAIL_*` settings in `.env`
3. Check service logs for SMTP errors

### Admin Password Lost

**Problem**: Can't login as admin

**Solution**:
1. Stop the service
2. Delete all users from database
3. Restart service (new admin user created with new credentials)

```sql
DELETE FROM logins;
DELETE FROM users;
```

## Support

For issues or questions:
- Check the main project documentation: `../../README.md`
- Review CLAUDE.md for architecture details: `../../CLAUDE.md`
- File issues at: https://github.com/tendant/simple-idm/issues

## License

Same as the parent Simple IDM project.
