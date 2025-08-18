# OIDC/OAuth2 SSO Flow Implementation

This document describes the implementation of the OAuth2 Authorization Code flow in simple-idm, turning it into an identity provider that can be used for Single Sign-On (SSO).

## Overview

The implementation adds OAuth2/OIDC capabilities to simple-idm, allowing it to act as an identity provider for other applications. This enables SSO scenarios where users can authenticate once with simple-idm and access multiple applications without re-entering credentials.

## Architecture

### Components Added

1. **OAuth2 Client Management** (`pkg/oauth2client/`)
   - `client.go`: Defines OAuth2 client structure and validation
   - `service.go`: Manages OAuth2 clients and validates authorization requests

2. **OIDC API** (`pkg/oidc/api/`)
   - `oidc.yaml`: OpenAPI specification for OAuth2 endpoints
   - `oidc.gen.go`: Generated Go code from OpenAPI spec
   - `handle.go`: HTTP handlers implementing OAuth2 authorization endpoint

3. **Demo Client** (`demo/oauth2-client/`)
   - Complete OAuth2 client application demonstrating the flow
   - Web interface showing the authorization process

## OAuth2 Authorization Code Flow

### Step 1: Authorization Request
```
GET /api/idm/oauth2/authorize?
    client_id=golang_app&
    redirect_uri=http://localhost:8181/demo/callback&
    response_type=code&
    scope=openid profile email&
    state=random_state_value
```

### Step 2: User Authentication
- If user is not authenticated, redirect to login page
- User logs in with existing simple-idm credentials
- After successful login, user is redirected back to authorization endpoint

### Step 3: Authorization Code Generation
- Validate client credentials and redirect URI
- Generate temporary authorization code (10-minute expiration)
- Redirect back to client with authorization code

### Step 4: Token Exchange
```
POST /api/idm/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
client_id=golang_app&
client_secret=golang_secret&
redirect_uri=http://localhost:8181/demo/callback
```

## Implementation Details

### OAuth2 Client Configuration

Default clients are configured in `pkg/oauth2client/client.go`:

```go
var DefaultClients = map[string]*OAuth2Client{
    "golang_app": {
        ClientID:     "golang_app",
        ClientSecret: "golang_secret",
        RedirectURIs: []string{
            "http://localhost:8181/demo/callback",
        },
        ResponseTypes: []string{"code"},
        Scopes:       []string{"openid", "profile", "email"},
    },
}
```

### Authorization Code Storage

Currently uses in-memory storage for authorization codes:
- Codes expire after 10 minutes
- Codes are single-use only
- Automatic cleanup of expired codes

### User Authentication Validation

The authorization endpoint validates user authentication by:
1. Checking Authorization header for Bearer token
2. Checking cookies for access_token
3. Validating JWT token using existing simple-idm JWT infrastructure

### Security Features

1. **State Parameter**: CSRF protection using random state values
2. **Code Expiration**: Authorization codes expire after 10 minutes
3. **Single Use**: Authorization codes can only be used once
4. **Client Validation**: Validates client ID, secret, and redirect URI
5. **Scope Validation**: Ensures requested scopes are allowed for the client

## API Endpoints

### Authorization Endpoint
- **URL**: `GET /api/idm/oauth2/authorize`
- **Parameters**:
  - `client_id` (required): OAuth2 client identifier
  - `redirect_uri` (required): Client's callback URL
  - `response_type` (required): Must be "code"
  - `scope` (optional): Requested scopes (space-separated)
  - `state` (optional): CSRF protection parameter

### Token Endpoint (Future Implementation)
- **URL**: `POST /api/idm/oauth2/token`
- **Purpose**: Exchange authorization code for access tokens
- **Status**: Not yet implemented - requires additional token management

## Demo Application

The demo client (`demo/oauth2-client/`) provides:

1. **Home Page**: Shows authentication status and flow explanation
2. **Login Flow**: Initiates OAuth2 authorization request
3. **Callback Handler**: Processes authorization code response
4. **Profile Page**: Displays token information
5. **Logout**: Clears session data

### Running the Demo

1. Start simple-idm server:
   ```bash
   cd simple-idm
   go run cmd/login/main.go
   ```

2. Start demo client:
   ```bash
   cd simple-idm/demo/oauth2-client
   go run main.go
   ```

3. Visit `http://localhost:8181` to start the demo

## Integration Points

### Existing simple-idm Integration

The OIDC implementation integrates with existing simple-idm components:

1. **JWT Authentication**: Reuses existing JWT validation for user authentication
2. **User Management**: Leverages existing user database and services
3. **Frontend Integration**: Redirects to existing frontend login pages when authentication is required

### Frontend Integration

The OIDC handler redirects unauthenticated users to the existing SolidJS frontend:

1. **Login Redirect**: `buildLoginRedirectURL()` redirects to `http://localhost:3000/login`
2. **External URL Handling**: Frontend Login.tsx and TwoFactorVerification.tsx handle external OAuth2 redirects
3. **Seamless Flow**: After successful login, users are redirected back to the OAuth2 authorization endpoint

### Main Application Integration

Added to `cmd/login/main.go`:
```go
// Initialize OAuth2 client service and OIDC handler
clientService := oauth2client.NewClientService()
oidcHandle := oidcapi.NewHandle(tokenAuth, clientService)

// Mount OIDC endpoints (public, no authentication required)
server.R.Mount("/", oidcapi.Handler(oidcHandle))
```

### Frontend Changes

Modified frontend components to handle OAuth2 flows:

1. **Login.tsx**: Added external URL redirect handling for OAuth2 callbacks
2. **TwoFactorVerification.tsx**: Added external URL redirect handling for 2FA flows
3. **Vite Configuration**: Proxy setup for OAuth2 endpoints to backend server

## Future Enhancements

### Token Endpoint Implementation
- Complete OAuth2 flow with token exchange
- Access token and refresh token generation
- Token introspection endpoint

### OIDC UserInfo Endpoint
- Provide user profile information
- Support standard OIDC claims
- Scope-based claim filtering

### Client Management
- Database storage for OAuth2 clients
- Admin interface for client registration
- Dynamic client registration

### Enhanced Security
- PKCE (Proof Key for Code Exchange) support
- JWT-based authorization codes
- Rate limiting and abuse protection

### Persistent Storage
- Database storage for authorization codes
- Session management improvements
- Audit logging

## Testing

### Manual Testing Flow

1. **Start Services**: Run both simple-idm and demo client
2. **Initiate Flow**: Click "Login with simple-idm" on demo client
3. **Authenticate**: Log in with simple-idm credentials if not already authenticated
4. **Verify Callback**: Confirm successful redirect with authorization code
5. **Check Token**: View token information on profile page

### Expected Behavior

- Unauthenticated users are redirected to login
- Authenticated users immediately get authorization code
- Invalid clients receive error responses
- State parameter is properly validated
- Authorization codes expire appropriately

## Configuration

### Environment Variables

The implementation uses existing simple-idm configuration:
- `JWT_SECRET`: Used for token validation
- Database connection settings for user authentication
- All existing login and authentication settings

### Client Registration

Currently, clients are hardcoded in `DefaultClients`. For production use, implement:
- Database-backed client storage
- Client registration API
- Admin interface for client management

## Conclusion

This implementation provides the foundation for using simple-idm as an OAuth2/OIDC identity provider. The authorization code flow is fully functional for the authorization phase, with the token exchange phase ready for implementation as the next step.

The modular design allows for easy extension and integration with existing simple-idm functionality while maintaining security best practices for OAuth2 flows.
