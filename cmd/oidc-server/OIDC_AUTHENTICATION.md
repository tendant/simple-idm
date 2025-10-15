# OIDC Authentication Integration

This document describes the OIDC (OpenID Connect) authentication integration between the AI Stock Analysis System and the Simple-IDM identity provider.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Authentication Flow](#authentication-flow)
- [Implementation Details](#implementation-details)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

The AI Stock Analysis System uses OAuth2/OIDC for authentication, delegating user authentication to an external identity provider (Simple-IDM). This provides:

- **Centralized authentication** - Single sign-on across multiple applications
- **Security isolation** - User credentials never touch the application
- **Standard protocol** - OAuth2/OIDC is a widely adopted industry standard
- **Flexible user management** - User accounts managed in dedicated IDM system

### Key Components

- **OIDC Provider**: Simple-IDM running on `http://localhost:4000`
- **Backend API**: FastAPI application on `http://localhost:8000`
- **Frontend**: SolidJS application on `http://localhost:5173`
- **Authentication Method**: Cookie-based JWT tokens

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Flow                           │
└─────────────────────────────────────────────────────────────────┘

1. User visits Frontend
   ↓
2. Frontend checks auth status (/api/v1/auth/me)
   ↓ (401 Unauthorized)
3. Redirect to /oidc/login
   ↓
4. Backend redirects to Simple-IDM authorize endpoint
   ↓
5. User authenticates with Simple-IDM
   ↓
6. Simple-IDM redirects to /oidc/callback with auth code
   ↓
7. Backend exchanges code for tokens with Simple-IDM
   ↓
8. Backend fetches user info from Simple-IDM
   ↓
9. Backend generates internal JWT token
   ↓
10. Backend sets HTTP-only cookie with JWT
    ↓
11. Backend redirects to Frontend
    ↓
12. Frontend automatically authenticated via cookie

┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Frontend   │◄───────►│   Backend    │◄───────►│  Simple-IDM  │
│  (SolidJS)   │  Cookie │   (FastAPI)  │  OIDC   │   (Go)       │
│   :5173      │  Auth   │    :8000     │  OAuth2 │   :4000      │
└──────────────┘         └──────────────┘         └──────────────┘
```

### Token Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        Token Types                               │
└─────────────────────────────────────────────────────────────────┘

Simple-IDM Tokens (RSA-256):
├── access_token  → Used to fetch user info from Simple-IDM
├── refresh_token → (Stored in cookie but not used by backend)
└── id_token      → (Optional, not used)

Backend JWT Token (HS-256):
└── auth_token    → HTTP-only cookie, used for all API requests
    ├── Algorithm: HS256
    ├── Secret: SECRET_KEY from .env
    ├── Expiry: 30 minutes (configurable)
    └── Claims:
        ├── sub: User ID from Simple-IDM
        ├── email: User email
        ├── name: User display name
        ├── username: Username
        ├── iat: Issued at timestamp
        ├── exp: Expiration timestamp
        ├── iss: "AI Stock Analysis System"
        └── aud: "AI Stock Analysis System"
```

## Configuration

### Environment Variables

Add the following to `.env`:

```bash
# =============================================================================
# SECURITY
# =============================================================================
# Secret key for JWT token signing and validation
# IMPORTANT: Change this in production to a secure random string
SECRET_KEY=your-secret-key-change-in-production

# =============================================================================
# OIDC AUTHENTICATION
# =============================================================================
# OIDC Provider Configuration (simple-idm)
OIDC_ENABLED=true
OIDC_PROVIDER_URL=http://localhost:4000
OIDC_CLIENT_ID=ai-stock-system
OIDC_CLIENT_SECRET=secret_e4df6242291042286d5251f48b044f10df5074a1b85776c53c2dde80122b0499
OIDC_REDIRECT_URI=http://localhost:5173/oidc/callback
OIDC_SCOPES=openid,profile,email

# Frontend URL for redirects after authentication
FRONTEND_URL=http://localhost:5173

# JWT Token Expiration
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Simple-IDM Configuration

Register the application as an OAuth2 client in Simple-IDM:

```bash
Client ID: ai-stock-system
Client Secret: secret_e4df6242291042286d5251f48b044f10df5074a1b85776c53c2dde80122b0499
Redirect URI: http://localhost:5173/oidc/callback
Scopes: openid, profile, email
Grant Types: authorization_code
```

### Vite Proxy Configuration

Frontend `vite.config.ts`:

```typescript
export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/oidc': 'http://localhost:8000',  // Proxy OIDC endpoints to backend
    }
  }
})
```

This ensures:
- OIDC endpoints are accessible from frontend origin
- Cookies set by backend are valid for frontend domain
- No CORS issues during authentication

## Authentication Flow

### 1. Login Initiation

**Endpoint**: `GET /oidc/login?redirect=/path`

**Process**:
```python
# src/api/v1/endpoints/oidc.py

1. Generate random state for CSRF protection
2. Store state with redirect path in memory
3. Build authorization URL with parameters:
   - client_id
   - response_type=code
   - scope=openid,profile,email
   - redirect_uri=http://localhost:5173/oidc/callback
   - state=<random_token>
4. Redirect user to Simple-IDM authorize endpoint
```

**Authorization URL**:
```
http://localhost:4000/api/idm/oauth2/authorize?
  client_id=ai-stock-system&
  response_type=code&
  scope=openid%20profile%20email&
  redirect_uri=http://localhost:5173/oidc/callback&
  state=<random_token>
```

### 2. User Authentication

User authenticates with Simple-IDM (outside our application):
- Username/password login
- 2FA if enabled
- Device recognition
- Account selection (if multiple)

### 3. Authorization Callback

**Endpoint**: `GET /oidc/callback?code=...&state=...`

**Process**:
```python
# src/api/v1/endpoints/oidc.py

1. Validate state parameter (CSRF protection)
2. Exchange authorization code for tokens:
   POST http://localhost:4000/api/idm/oauth2/token
   - grant_type=authorization_code
   - code=<auth_code>
   - redirect_uri=http://localhost:5173/oidc/callback
   - client_id=ai-stock-system
   - client_secret=<secret>

3. Receive tokens from Simple-IDM:
   - access_token (RSA-256 signed)
   - refresh_token
   - expires_in

4. Fetch user info using access token:
   GET http://localhost:4000/api/idm/oauth2/userinfo
   Authorization: Bearer <access_token>

5. Receive user information:
   - sub (user ID)
   - email
   - name
   - preferred_username

6. Generate backend JWT token (HS-256)
7. Set HTTP-only cookie with JWT
8. Redirect to frontend
```

### 4. JWT Token Generation

**Function**: `generate_backend_jwt(user_info)`

```python
# src/api/v1/endpoints/oidc.py

import time

now_timestamp = int(time.time())  # Use time.time() for proper UTC timestamp
expires_in = settings.access_token_expire_minutes * 60  # Default: 1800 seconds (30 min)
exp_timestamp = now_timestamp + expires_in

payload = {
    "sub": user_info.sub,              # User ID from Simple-IDM
    "email": user_info.email,          # User email
    "name": user_info.name,            # Display name
    "username": user_info.username,    # Username
    "iat": now_timestamp,              # Issued at (Unix timestamp)
    "exp": exp_timestamp,              # Expiration (Unix timestamp)
    "iss": "AI Stock Analysis System", # Issuer
    "aud": "AI Stock Analysis System", # Audience
}

token = jwt.encode(payload, settings.secret_key, algorithm="HS256")
```

**Important**: Use `time.time()` instead of `datetime.utcnow().timestamp()` to avoid timezone issues.

### 5. Cookie Setup

**Function**: `set_cookie()` in redirect response

```python
# src/api/v1/endpoints/oidc.py

response.set_cookie(
    key="auth_token",
    value=backend_token,
    max_age=expires_in,              # Cookie expiry matches token expiry
    httponly=True,                   # JavaScript cannot access
    secure=False,                    # True in production (HTTPS only)
    samesite="lax",                  # CSRF protection
    path="/",                        # Available for all paths
    # No domain parameter in development (lets browser set it automatically)
)
```

**Cookie Behavior**:
- Set during backend redirect (proxied through Vite)
- Automatically included in all API requests to same origin
- Browser handles cookie storage and transmission
- HTTP-only prevents JavaScript access (XSS protection)

### 6. Request Authentication

**Middleware**: `AuthenticationMiddleware`

```python
# src/core/auth_middleware.py

For each API request:

1. Check if path is public (skip auth for /oidc/*, /health, /docs)
2. Extract auth_token from cookie
3. Validate JWT token:
   - Verify signature with SECRET_KEY
   - Check expiration (with 10 second leeway for clock skew)
   - Skip audience validation (verify_aud=False)
4. Attach user info to request.state.user:
   - id (from sub claim)
   - username
   - email
   - name
5. Continue to endpoint handler
6. On validation failure, return 401 Unauthorized
```

**Public Paths** (no authentication required):
```python
PUBLIC_PATHS = [
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/oidc/login",
    "/oidc/callback",
    "/api/v1/auth/logout",
]

PUBLIC_PREFIXES = ["/oidc/"]
```

### 7. User Info Endpoint

**Endpoint**: `GET /api/v1/auth/me`

```python
# src/api/v1/endpoints/auth.py

# Middleware has already validated token and attached user to request.state
user_data = request.state.user

return {
    "user": {
        "id": user_data["id"],
        "username": user_data["username"],
        "email": user_data.get("email"),
        "name": user_data.get("name")
    }
}
```

### 8. Frontend Integration

**Service**: `authService.ts`

```typescript
// frontend/src/services/authService.ts

class AuthService {
  async getCurrentUser(): Promise<User> {
    const response = await fetch('/api/v1/auth/me', {
      credentials: 'include',  // Include cookies
    });

    if (response.status === 401) {
      throw new Error('Unauthorized');
    }

    const data = await response.json();
    return data.user;
  }

  redirectToLogin(): void {
    const currentPath = window.location.pathname + window.location.search;
    const shouldPreserveRedirect =
      !currentPath.startsWith('/auth') &&
      !currentPath.startsWith('/login') &&
      !currentPath.startsWith('/oidc');
    const redirectPath = shouldPreserveRedirect ? currentPath : '/';

    // Proxied through Vite to backend
    window.location.href = `/oidc/login?redirect=${encodeURIComponent(redirectPath)}`;
  }

  logout(): void {
    window.location.href = '/api/v1/auth/logout';
  }
}
```

**App Component**: `App.tsx`

```typescript
// frontend/src/App.tsx

onMount(async () => {
  try {
    const currentUser = await authService.getCurrentUser();
    setUser(currentUser);
  } catch (err) {
    // Not authenticated - redirect to login
    authService.redirectToLogin();
  }
});
```

## Implementation Details

### Backend Files

**OIDC Endpoints** (`src/api/v1/endpoints/oidc.py`):
- `GET /oidc/login` - Initiate OIDC login flow
- `GET /oidc/callback` - Handle OAuth2 callback from Simple-IDM
- `POST /oidc/logout` - Clear authentication cookie

**Auth Endpoints** (`src/api/v1/endpoints/auth.py`):
- `GET /api/v1/auth/me` - Get current user info
- `POST /api/v1/auth/logout` - Logout (clear cookie)

**Authentication Middleware** (`src/core/auth_middleware.py`):
- Validates JWT token from cookie on all protected endpoints
- Attaches user info to `request.state.user`
- Returns 401 for invalid/missing tokens

**Configuration** (`src/core/config.py`):
- `secret_key` - JWT signing key (must match between token generation and validation)
- `algorithm` - JWT algorithm (HS256)
- `access_token_expire_minutes` - Token expiration time
- `oidc_*` - OIDC provider configuration

### Frontend Files

**Auth Service** (`frontend/src/services/authService.ts`):
- `getCurrentUser()` - Fetch current user from backend
- `redirectToLogin()` - Redirect to OIDC login
- `handleUnauthorized()` - Handle 401 errors
- `logout()` - Clear session and logout

**App Component** (`frontend/src/App.tsx`):
- Checks authentication on mount
- Shows loading state during auth check
- Redirects to login if not authenticated
- Renders main app when authenticated

**Vite Config** (`frontend/vite.config.ts`):
- Proxies `/api/*` to backend
- Proxies `/oidc/*` to backend
- Enables cookie forwarding

## Security Considerations

### Token Security

**JWT Secret Key**:
- Must be strong and random in production
- Same key must be used for signing and validation
- Never commit to version control
- Store in `.env` file (git-ignored)

```bash
# Generate secure random key
openssl rand -base64 32
```

**Token Storage**:
- Stored in HTTP-only cookie (not accessible to JavaScript)
- Prevents XSS attacks from stealing tokens
- Browser automatically includes in requests
- SameSite=Lax prevents CSRF attacks

**Token Expiration**:
- Default: 30 minutes
- Configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`
- Enforced by middleware on every request
- 10 second leeway for clock skew

### Cookie Security

**Development** (HTTP):
```python
httponly=True      # Prevent JavaScript access
secure=False       # Allow HTTP (development only)
samesite="lax"     # CSRF protection
path="/"           # Available for all paths
# No domain set    # Let browser determine
```

**Production** (HTTPS):
```python
httponly=True      # Prevent JavaScript access
secure=True        # HTTPS only
samesite="strict"  # Stronger CSRF protection
path="/"           # Available for all paths
domain=None        # Current domain only
```

### CSRF Protection

**State Parameter**:
- Random token generated for each login request
- Stored server-side with timestamp
- Validated on callback
- Expires after 10 minutes
- Prevents replay attacks

**Cookie SameSite**:
- `lax` in development
- `strict` in production
- Prevents cross-site request forgery

### OIDC Security

**Client Secret**:
- Shared secret between application and Simple-IDM
- Used to authenticate token exchange requests
- Never sent to frontend
- Stored securely in `.env`

**Authorization Code Flow**:
- More secure than implicit flow
- Code exchanged server-side for tokens
- Client secret required for exchange
- Prevents token interception

**HTTPS in Production**:
- All OIDC communication must use HTTPS
- Protects tokens in transit
- Required by OAuth2 specification
- Set `secure=True` for cookies

## Troubleshooting

### Common Issues

#### 1. Infinite Redirect Loop

**Symptoms**: User redirected to login repeatedly after successful authentication

**Causes**:
- Cookie not being set correctly
- Cookie not being sent with requests
- Token validation failing silently

**Solutions**:
- Check browser dev tools → Application → Cookies
- Verify `auth_token` cookie is present
- Check cookie domain and path
- Verify backend logs for validation errors

#### 2. Token Validation Fails

**Symptoms**: `401 Unauthorized` with "Invalid authentication token"

**Causes**:
- Secret key mismatch between generation and validation
- Timezone issues causing `iat` in future
- Audience validation enabled
- Token expired

**Solutions**:
```bash
# Verify SECRET_KEY is set in .env
grep SECRET_KEY .env

# Check token contents
python -c "
import jwt
token = 'YOUR_TOKEN_HERE'
print(jwt.decode(token, options={'verify_signature': False}))
"

# Verify token signature
python -c "
import jwt
token = 'YOUR_TOKEN_HERE'
secret = 'your-secret-key-change-in-production'
try:
    jwt.decode(token, secret, algorithms=['HS256'], options={'verify_aud': False})
    print('Token is valid')
except Exception as e:
    print(f'Token invalid: {e}')
"
```

#### 3. Timezone Issues

**Symptoms**: Token validation fails with "not yet valid" error

**Cause**: Using `datetime.utcnow().timestamp()` incorrectly

**Solution**: Use `time.time()` for Unix timestamps:
```python
import time

now_timestamp = int(time.time())  # Correct
# NOT: datetime.utcnow().timestamp()  # Incorrect
```

#### 4. Cookie Not Set

**Symptoms**: No `auth_token` cookie in browser after login

**Causes**:
- Domain mismatch
- Vite proxy not forwarding cookies
- Backend redirect not going through proxy

**Solutions**:
- Don't set `domain` parameter in development
- Verify redirect URI uses frontend URL (http://localhost:5173)
- Check Vite proxy configuration
- Ensure cookie path is `/`

#### 5. CORS Issues

**Symptoms**: CORS errors in browser console

**Causes**:
- Frontend and backend on different origins
- Proxy not configured correctly

**Solutions**:
- Ensure Vite proxy is configured for `/api` and `/oidc`
- Add frontend URL to `allowed_origins` in backend config
- Set `allow_credentials: true` in CORS config

### Debug Checklist

```bash
# 1. Verify environment variables
grep -E "(SECRET_KEY|OIDC_)" .env

# 2. Check backend is running
curl http://localhost:8000/health

# 3. Check Simple-IDM is running
curl http://localhost:4000/.well-known/openid-configuration

# 4. Test OIDC login redirect
curl -v http://localhost:8000/oidc/login

# 5. Check token validation
# (See "Token Validation Fails" section above)

# 6. Verify Vite proxy
# Check vite.config.ts has /api and /oidc proxies

# 7. Check browser cookies
# Open DevTools → Application → Cookies → http://localhost:5173
# Look for auth_token cookie

# 8. Check backend logs
# Look for authentication success/failure messages
# Middleware logs validation errors
```

### Logging

**Backend Logging**:
```python
# Enable debug logging in .env
LOG_LEVEL=DEBUG

# OIDC flow logs:
logger.info(f"Redirecting to OIDC provider: {auth_url}")
logger.info(f"Generated backend JWT for user: {user_info.sub}")
logger.info(f"[oidc-callback] Cookie set via proxy, redirecting to: {url}")

# Middleware logs:
logger.info(f"✅ Cookie auth successful for user {user_id} on path: {path}")
logger.warning(f"No auth token cookie found for protected path: {path}")
logger.warning(f"Invalid token for path {path}: {error}")
```

**Frontend Logging**:
```typescript
// Enable console logs
console.log('[AuthService] Current path:', currentPath);
console.log('[AuthService] Redirecting to OIDC login:', loginUrl);
console.error('Failed to get current user:', error);
```

## Production Deployment

### Configuration Changes

**Environment Variables**:
```bash
# Production secret key (generate new random key)
SECRET_KEY=<generate-with-openssl-rand-base64-32>

# Use production OIDC provider
OIDC_PROVIDER_URL=https://idm.yourdomain.com

# Use production URLs
OIDC_REDIRECT_URI=https://app.yourdomain.com/oidc/callback
FRONTEND_URL=https://app.yourdomain.com

# Enable HTTPS-only cookies
ENVIRONMENT=production
```

**Cookie Settings**:
```python
# Automatically applied in production environment
response.set_cookie(
    key="auth_token",
    value=token,
    httponly=True,
    secure=True,          # HTTPS only
    samesite="strict",    # Stronger CSRF protection
    path="/",
)
```

**CORS Configuration**:
```python
# Update allowed origins
allowed_origins = [
    "https://app.yourdomain.com",
]
```

### Security Checklist

- [ ] Generate new random `SECRET_KEY`
- [ ] Enable HTTPS for all services
- [ ] Set `secure=True` for cookies
- [ ] Update `OIDC_PROVIDER_URL` to production IDM
- [ ] Update `OIDC_REDIRECT_URI` to production app
- [ ] Update `FRONTEND_URL` to production domain
- [ ] Configure production CORS origins
- [ ] Disable API documentation (`docs_url=None`)
- [ ] Set `ENVIRONMENT=production`
- [ ] Review and update OIDC client configuration in Simple-IDM
- [ ] Enable rate limiting
- [ ] Set up monitoring and logging
- [ ] Test authentication flow thoroughly
- [ ] Verify token expiration works correctly
- [ ] Test logout functionality

## References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [Simple-IDM Documentation](../simple-idm/CLAUDE.md)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [SolidJS Documentation](https://www.solidjs.com/)
