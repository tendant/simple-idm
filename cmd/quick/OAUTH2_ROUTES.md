# OAuth2/OIDC Routes in Quick Server

## Updated Route Structure (Following Industry Standards)

### User-Facing Endpoint (No `/api` prefix)
**Authorization endpoint** - where users are redirected for OAuth2 login:
- `GET /oauth2/authorize` - OAuth2 authorization endpoint (browser redirects)

### API Endpoints (With `/api` prefix)
These are programmatic API calls, not user-facing:
- `POST /api/oauth2/token` - Token endpoint (exchange code for access token)
- `GET /api/oauth2/userinfo` - UserInfo endpoint (get user details with token)
- `GET /api/oauth2/jwks` - JWKS endpoint (public keys for token verification)

### Discovery Endpoints
- `GET /.well-known/openid-configuration` - OIDC discovery metadata
- `GET /.well-known/oauth-authorization-server` - OAuth2 server metadata
- `GET /.well-known/oauth-protected-resource` - Resource server metadata

## Why This Structure?

### Industry Standard Practice
Most OAuth2/OIDC providers follow this pattern:
- **Google**: `/o/oauth2/v2/auth` (authorize), `/token` (API)
- **GitHub**: `/login/oauth/authorize` (user-facing), `/login/oauth/access_token` (API)
- **Microsoft**: `/oauth2/v2.0/authorize` (user-facing), `/oauth2/v2.0/token` (API)
- **Keycloak**: `/protocol/openid-connect/auth` (authorize), `/protocol/openid-connect/token` (API)

### Rationale
1. **Authorization endpoint** (`/oauth2/authorize`) is user-facing - users are redirected here via their browser
2. **Token, UserInfo, JWKS endpoints** are API calls - invoked programmatically by applications
3. Separating them makes it clear which endpoints are for humans vs machines

## Example OAuth2 Flow

### Step 1: Redirect user to authorization endpoint
```
http://localhost:4000/oauth2/authorize?
  client_id=your_client_id&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  scope=openid profile email&
  state=random_state_value&
  code_challenge=base64url_challenge&
  code_challenge_method=S256
```

### Step 2: User logs in (if not already authenticated)
The authorization endpoint handles the login flow and consent.

### Step 3: User is redirected back with authorization code
```
http://localhost:3000/callback?
  code=authorization_code&
  state=random_state_value
```

### Step 4: Exchange code for tokens (API call)
```bash
curl -X POST http://localhost:4000/api/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=authorization_code" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret" \
  -d "code_verifier=original_code_verifier"
```

### Step 5: Get user info (API call)
```bash
curl http://localhost:4000/api/oauth2/userinfo \
  -H "Authorization: Bearer access_token"
```

## Discovery

View full OIDC configuration:
```bash
curl http://localhost:4000/.well-known/openid-configuration
```

Example response:
```json
{
  "issuer": "http://localhost:4000",
  "authorization_endpoint": "http://localhost:4000/oauth2/authorize",
  "token_endpoint": "http://localhost:4000/api/oauth2/token",
  "userinfo_endpoint": "http://localhost:4000/api/oauth2/userinfo",
  "jwks_uri": "http://localhost:4000/api/oauth2/jwks",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"]
}
```

## Changes Made

### 1. Route Registration (`cmd/quick/main.go`)
- Added separate `/oauth2/authorize` route (user-facing)
- Kept `/api/oauth2/*` for API endpoints (token, userinfo, jwks)

### 2. Well-Known Metadata (`pkg/wellknown/metadata.go`)
Updated endpoint URLs to match new structure:
- `authorization_endpoint`: `/oauth2/authorize` (was `/api/oauth2/authorize`)
- `token_endpoint`: `/api/oauth2/token` (unchanged)
- `userinfo_endpoint`: `/api/oauth2/userinfo` (unchanged)
- `jwks_uri`: `/api/oauth2/jwks` (unchanged)

## Testing

### Test authorization endpoint
```bash
# Should redirect or show login page
curl "http://localhost:4000/oauth2/authorize?client_id=test&redirect_uri=http://localhost/callback&response_type=code&scope=openid"
```

### Test discovery
```bash
curl http://localhost:4000/.well-known/openid-configuration | jq .
```

### Verify endpoints match discovery
The endpoints advertised in the discovery document should now match the actual routes.
