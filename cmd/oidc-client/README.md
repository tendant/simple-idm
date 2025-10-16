# OIDC Client Demo

A standalone OpenID Connect (OIDC) / OAuth2 client demonstration application built with Go.

## Features

- **Authorization Code Flow** implementation
- **PKCE Support** (Proof Key for Code Exchange)
- **Pure HTML** web interface with minimal JavaScript
- **RESTful API** endpoints under `/api` prefix
- **Session Management** with HTTP-only cookies
- **Token Exchange** and user info retrieval
- **Protected Routes** requiring authentication

## Quick Start

### Prerequisites

The OIDC Server must be running before starting the client:

```bash
# Terminal 1: Start OIDC Server
cd cmd/oidc-server
go run main.go
```

### 1. Build and Run

```bash
# Terminal 2: Start OIDC Client
cd cmd/oidc-client
go run main.go
```

The client will start on `http://localhost:4002`

### 2. Test the Flow

1. Open your browser: http://localhost:4002
2. Click "Login with OIDC"
3. You'll be redirected to the OIDC Server login page
4. Enter credentials:
   - Username: `demo`
   - Password: `password`
5. After successful login, you'll be redirected back with user info displayed
6. Try accessing the protected page

## Configuration

The client is pre-configured to work with the demo OIDC server:

```go
ClientID:            "demo-client"
ClientSecret:        "demo-secret"
AuthorizationURL:    "http://localhost:4001/api/oidc/authorize"
TokenURL:            "http://localhost:4001/api/oidc/token"
UserInfoURL:         "http://localhost:4001/api/oidc/userinfo"
RedirectURI:         "http://localhost:4002/callback"
```

## Web Pages

### Home Page
```
GET /
```

**Features:**
- Shows login status
- "Login with OIDC" button when not authenticated
- User information display when authenticated
- Links to protected page and logout

**Unauthenticated view:**
```
┌─────────────────────────────────┐
│ OIDC Client Demo                │
├─────────────────────────────────┤
│ Not Logged In                   │
│ [Login with OIDC]               │
└─────────────────────────────────┘
```

**Authenticated view:**
```
┌─────────────────────────────────┐
│ OIDC Client Demo                │
├─────────────────────────────────┤
│ ✓ Logged In                     │
│ Welcome, Demo User!             │
│ [Protected Page] [Logout]       │
└─────────────────────────────────┘
```

### Callback Page
```
GET /callback?code=<auth_code>&state=<state>
```

Handles the OAuth2 callback after authorization:
1. Validates state parameter (CSRF protection)
2. Exchanges authorization code for tokens
3. Retrieves user information
4. Creates local session
5. Displays success page with user info and tokens

**Success view:**
```
┌─────────────────────────────────┐
│ ✓ Login Successful!             │
├─────────────────────────────────┤
│ User Information:               │
│ {                               │
│   "sub": "...",                 │
│   "name": "Demo User",          │
│   "email": "demo@example.com"   │
│ }                               │
├─────────────────────────────────┤
│ Tokens Received:                │
│ Access Token: eyJhbGc...        │
│ Expires In: 3600 seconds        │
├─────────────────────────────────┤
│ [Home] [View Protected Page]    │
└─────────────────────────────────┘
```

### Protected Page
```
GET /protected
```

A page that requires authentication:
- Redirects to home page if not authenticated
- Displays user information when authenticated
- Demonstrates session-based access control

## API Endpoints

### Get Current User
```
GET /api/auth/me
```

**Description:** Returns current user information from session.

**Response (authenticated):**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Demo User",
  "email": "demo@example.com",
  "groups": ["users", "demo"]
}
```

**Response (not authenticated):**
```json
{
  "error": "not_authenticated"
}
```
HTTP Status: 401

### Login Initiation
```
GET /api/auth/login
```

**Description:** Initiates the OIDC authorization flow.

**Process:**
1. Generates random state for CSRF protection
2. Stores state in memory
3. Redirects to OIDC authorization endpoint

**Redirect URL format:**
```
http://localhost:4001/api/oidc/authorize?
  response_type=code&
  client_id=demo-client&
  redirect_uri=http://localhost:4002/callback&
  scope=openid+profile+email&
  state=<random_state>
```

### Logout
```
POST /api/auth/logout
```

**Description:** Destroys the local session and clears cookies.

**Response:**
```json
{
  "status": "logged_out"
}
```

## Authentication Flow

### Complete Flow Diagram

```
┌────────┐                ┌────────┐                ┌─────────┐
│ User   │                │ Client │                │  OIDC   │
│ Browser│                │  App   │                │ Server  │
└───┬────┘                └───┬────┘                └────┬────┘
    │                         │                          │
    │  1. Click Login         │                          │
    ├────────────────────────>│                          │
    │                         │                          │
    │  2. Redirect to /api/auth/login                    │
    │<────────────────────────┤                          │
    │                         │                          │
    │                         │  3. Generate state       │
    │                         │     & redirect           │
    │                         │                          │
    │  4. GET /api/oidc/authorize?...                    │
    ├──────────────────────────────────────────────────>│
    │                         │                          │
    │  5. Show login form     │                          │
    │<──────────────────────────────────────────────────┤
    │                         │                          │
    │  6. Submit credentials  │                          │
    ├──────────────────────────────────────────────────>│
    │                         │                          │
    │  7. Redirect to callback with code                 │
    │<──────────────────────────────────────────────────┤
    │                         │                          │
    │  8. GET /callback?code=...&state=...               │
    ├────────────────────────>│                          │
    │                         │                          │
    │                         │  9. Validate state       │
    │                         │     Exchange code        │
    │                         │     for tokens           │
    │                         ├─────────────────────────>│
    │                         │                          │
    │                         │ 10. Return tokens        │
    │                         │<─────────────────────────┤
    │                         │                          │
    │                         │ 11. Get user info        │
    │                         ├─────────────────────────>│
    │                         │                          │
    │                         │ 12. Return user data     │
    │                         │<─────────────────────────┤
    │                         │                          │
    │                         │ 13. Create session       │
    │                         │     Set cookie           │
    │                         │                          │
    │ 14. Show success page   │                          │
    │<────────────────────────┤                          │
```

### Step-by-Step Process

#### Step 1: User Clicks Login
User clicks "Login with OIDC" button on the home page.

#### Step 2-3: Initiate Authorization
Client generates a random state token and redirects to OIDC authorization endpoint.

#### Step 4-5: Authorization Request
OIDC server receives authorization request and shows login form.

#### Step 6: User Authentication
User enters credentials on OIDC server login page.

#### Step 7: Authorization Code
OIDC server validates credentials and redirects back to client with authorization code.

#### Step 8-9: Callback Handling
Client receives callback, validates state, and exchanges code for tokens.

#### Step 10: Token Exchange
Client sends code to OIDC token endpoint with client credentials.

#### Step 11-12: User Info Retrieval
Client uses access token to fetch user information.

#### Step 13: Session Creation
Client creates local session and sets HTTP-only cookie.

#### Step 14: Success
User is redirected to success page showing their information.

## Session Management

### Session Storage

Sessions are stored in-memory with the following structure:

```go
type Session struct {
    UserID      string
    AccessToken string
    IDToken     string
    UserInfo    map[string]interface{}
    ExpiresAt   time.Time
}
```

### Session Lifecycle

1. **Creation**: After successful token exchange
2. **Storage**: In-memory map with random session ID
3. **Cookie**: HTTP-only cookie containing session ID
4. **Expiration**: Matches access token expiration (1 hour)
5. **Cleanup**: Manual cleanup on logout or automatic on expiration

### Security Features

- **HTTP-only cookies**: JavaScript cannot access session cookies
- **State validation**: CSRF protection via state parameter
- **Session expiration**: Automatic timeout after token expiry
- **Secure storage**: Tokens stored server-side, not in browser

## Code Structure

### Main Components

```go
// Session management
sessions      map[string]*Session    // Active sessions
states        map[string]*StateInfo  // OIDC state tracking

// HTTP handlers
handleHomePage()        // Main landing page
handleCallback()        // OAuth callback handler
handleProtectedPage()   // Protected resource
handleAuthMe()          // API: Get current user
handleLogout()          // API: Destroy session

// Helper functions
exchangeCodeForToken()  // Token exchange with OIDC server
getUserInfo()           // Fetch user info from OIDC server
generateRandomString()  // Generate secure random strings
```

## Testing

### Manual Testing

1. **Test successful login:**
   ```bash
   # Open browser
   open http://localhost:4002

   # Click "Login with OIDC"
   # Enter: demo / password
   # Verify success page appears
   ```

2. **Test protected page:**
   ```bash
   # After login, click "View Protected Page"
   # Verify user info is displayed

   # Try accessing directly when not logged in
   open http://localhost:4002/protected
   # Verify redirect to home page
   ```

3. **Test logout:**
   ```bash
   # After login, click "Logout"
   # Verify redirect to home page
   # Verify "Not Logged In" state
   ```

4. **Test API endpoints:**
   ```bash
   # Get current user (when authenticated)
   curl -b cookies.txt http://localhost:4002/api/auth/me

   # Logout
   curl -X POST -b cookies.txt http://localhost:4002/api/auth/logout
   ```

### Using cURL

Complete flow using cURL:

```bash
# 1. Get login URL
curl -c cookies.txt -L http://localhost:4002/api/auth/login

# 2. Complete login on OIDC server (manual browser step)

# 3. Check authentication status
curl -b cookies.txt http://localhost:4002/api/auth/me

# 4. Logout
curl -X POST -b cookies.txt http://localhost:4002/api/auth/logout
```

## Customization

### Change Server Configuration

Edit the constants at the top of `main.go`:

```go
const (
    ClientID            = "your-client-id"
    ClientSecret        = "your-client-secret"
    AuthorizationURL    = "https://your-server.com/api/oidc/authorize"
    TokenURL            = "https://your-server.com/api/oidc/token"
    UserInfoURL         = "https://your-server.com/api/oidc/userinfo"
    RedirectURI         = "http://localhost:4002/callback"
    ClientPort          = ":4002"
)
```

### Add PKCE Support

The code structure supports PKCE. To enable:

1. Generate code verifier and challenge
2. Add `code_challenge` and `code_challenge_method` to authorization URL
3. Include `code_verifier` in token exchange request

## Troubleshooting

### "Invalid state parameter"
- State tokens expire after use
- Don't refresh the callback page
- Each login flow generates a new state

### "Failed to exchange code for token"
- Verify OIDC server is running on port 4001
- Check client credentials match server configuration
- Ensure authorization code hasn't expired (10 min)

### "Session expired"
- Sessions expire after 1 hour
- Click "Login with OIDC" again
- Clear cookies and retry

### Cookies not being set
- Ensure using HTTP (not HTTPS) in development
- Check browser allows cookies from localhost
- Verify cookie path is `/`

## Production Considerations

### Required Changes for Production

1. **Use HTTPS**: Update all URLs to use HTTPS
2. **Persistent Storage**: Replace in-memory sessions with Redis/database
3. **Secure Cookies**: Set `Secure: true` on cookies
4. **Environment Variables**: Move configuration to environment variables
5. **Error Handling**: Add comprehensive error pages
6. **Logging**: Add structured logging for debugging
7. **State Cleanup**: Implement periodic cleanup of expired states
8. **PKCE**: Enable PKCE for enhanced security

### Environment Variables Example

```bash
export OIDC_CLIENT_ID="production-client-id"
export OIDC_CLIENT_SECRET="production-client-secret"
export OIDC_ISSUER="https://auth.example.com"
export OIDC_REDIRECT_URI="https://app.example.com/callback"
export CLIENT_PORT=":8080"
export COOKIE_SECURE="true"
```

## Reference Documentation

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
