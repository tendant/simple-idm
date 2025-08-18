# External Provider Support for Simple-IDM

This package provides OAuth2-based external identity provider support for Simple-IDM, allowing users to authenticate using third-party services like Google, Microsoft, GitHub, and other OAuth2-compliant providers.

## Features

- **Multiple Provider Support**: Support for Google, Microsoft, GitHub, LinkedIn, and custom OAuth2 providers
- **Secure OAuth2 Flow**: Complete OAuth2 authorization code flow with CSRF protection
- **User Mapping**: Automatic mapping of external user data to internal user accounts
- **Token Management**: JWT token generation and cookie-based session management
- **RESTful API**: Clean HTTP API for provider listing and authentication flows
- **Extensible Architecture**: Easy to add new providers or customize existing ones

## Architecture

The external provider system consists of several key components:

### Core Components

1. **ExternalProvider**: Data model representing an OAuth2 provider configuration
2. **ExternalProviderRepository**: Storage interface for provider configurations
3. **ExternalProviderService**: Business logic for OAuth2 flows and user authentication
4. **API Handler**: HTTP endpoints for provider listing and OAuth2 flows

### Flow Diagram

```
Frontend → List Providers → Display Login Options
    ↓
User Clicks "Login with Google"
    ↓
Frontend → /auth/google → Redirect to Google OAuth2
    ↓
User Authenticates with Google
    ↓
Google → /auth/google/callback → Exchange Code for Token
    ↓
Fetch User Info → Map to Internal User → Generate JWT → Set Cookies
    ↓
Redirect to Frontend with Success
```

## API Endpoints

### GET /auth/providers
Lists all enabled external providers.

**Response:**
```json
{
  "providers": [
    {
      "id": "google",
      "name": "google",
      "display_name": "Google",
      "enabled": true,
      "icon_url": "https://developers.google.com/identity/images/g-logo.png",
      "description": "Sign in with your Google account"
    }
  ]
}
```

### GET /auth/{provider}
Initiates OAuth2 flow for the specified provider.

**Parameters:**
- `provider` (path): Provider ID (e.g., "google", "microsoft")
- `redirect_url` (query, optional): URL to redirect after successful authentication

**Response:** HTTP 302 redirect to provider's OAuth2 authorization URL

### GET /auth/{provider}/callback
Handles OAuth2 callback from the provider.

**Parameters:**
- `provider` (path): Provider ID
- `code` (query): Authorization code from provider
- `state` (query): CSRF protection state parameter
- `error` (query, optional): Error code if authentication failed
- `error_description` (query, optional): Human-readable error description

**Response:** HTTP 302 redirect to frontend with authentication result

## Setup and Configuration

### 1. Initialize Repository

```go
// In-memory repository (for development)
repository := externalprovider.NewInMemoryExternalProviderRepository()

// Or implement your own persistent repository
// repository := NewDatabaseExternalProviderRepository(db)
```

### 2. Configure Providers

```go
// Google OAuth2 configuration
googleProvider := &externalprovider.ExternalProvider{
    ID:           "google",
    Name:         "google",
    DisplayName:  "Google",
    ClientID:     "your-google-client-id.apps.googleusercontent.com",
    ClientSecret: "your-google-client-secret",
    AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
    TokenURL:     "https://oauth2.googleapis.com/token",
    UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
    Scopes:       []string{"openid", "profile", "email"},
    Enabled:      true,
    IconURL:      "https://developers.google.com/identity/images/g-logo.png",
    Description:  "Sign in with your Google account",
}

err := repository.CreateProvider(googleProvider)
if err != nil {
    log.Fatal("Failed to create Google provider:", err)
}
```

### 3. Create Service

```go
serviceOptions := &externalprovider.ExternalProviderServiceOptions{
    BaseURL:         "http://localhost:4000",
    StateExpiration: 10 * 60, // 10 minutes
    HTTPClient:      &http.Client{},
}

externalProviderService := externalprovider.NewExternalProviderService(
    repository,
    loginService,      // Your existing login service
    userMapper,        // Your user mapping implementation
    serviceOptions,
)
```

### 4. Setup HTTP Handler

```go
import externalProviderAPI "github.com/tendant/simple-idm/pkg/externalprovider/api"

// Create API handler
handle := externalProviderAPI.NewHandle(
    externalProviderService,
    loginService,
    tokenService,
    tokenCookieService,
).WithFrontendURL("http://localhost:3000")

// Mount endpoints
httpHandler := externalProviderAPI.Handler(handle)
router.Mount("/", httpHandler)
```

## Provider Configuration

### Google OAuth2

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth2 credentials
5. Add authorized redirect URI: `http://localhost:4000/auth/google/callback`

```go
googleProvider := &externalprovider.ExternalProvider{
    ID:           "google",
    Name:         "google",
    DisplayName:  "Google",
    ClientID:     "your-client-id.apps.googleusercontent.com",
    ClientSecret: "your-client-secret",
    AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
    TokenURL:     "https://oauth2.googleapis.com/token",
    UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
    Scopes:       []string{"openid", "profile", "email"},
    Enabled:      true,
}
```

### Microsoft OAuth2

1. Go to [Azure Portal](https://portal.azure.com/)
2. Register a new application
3. Add redirect URI: `http://localhost:4000/auth/microsoft/callback`
4. Generate client secret

```go
microsoftProvider := &externalprovider.ExternalProvider{
    ID:           "microsoft",
    Name:         "microsoft",
    DisplayName:  "Microsoft",
    ClientID:     "your-application-id",
    ClientSecret: "your-client-secret",
    AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
    Scopes:       []string{"openid", "profile", "email", "User.Read"},
    Enabled:      true,
}
```

### GitHub OAuth2

1. Go to [GitHub Developer Settings](https://github.com/settings/applications/new)
2. Create a new OAuth App
3. Set Authorization callback URL: `http://localhost:4000/auth/github/callback`

```go
githubProvider := &externalprovider.ExternalProvider{
    ID:           "github",
    Name:         "github",
    DisplayName:  "GitHub",
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    AuthURL:      "https://github.com/login/oauth/authorize",
    TokenURL:     "https://github.com/login/oauth/access_token",
    UserInfoURL:  "https://api.github.com/user",
    Scopes:       []string{"user:email"},
    Enabled:      true,
}
```

## User Mapping

The system requires a `UserMapper` implementation to convert external user data to internal user accounts:

```go
type UserMapper interface {
    MapExternalUser(providerID string, externalUser map[string]interface{}) (*User, error)
}
```

Example implementation:

```go
func (m *MyUserMapper) MapExternalUser(providerID string, externalUser map[string]interface{}) (*User, error) {
    switch providerID {
    case "google":
        return &User{
            Email:     externalUser["email"].(string),
            FirstName: externalUser["given_name"].(string),
            LastName:  externalUser["family_name"].(string),
            AvatarURL: externalUser["picture"].(string),
        }, nil
    case "github":
        return &User{
            Email:     externalUser["email"].(string),
            FirstName: externalUser["name"].(string),
            Username:  externalUser["login"].(string),
            AvatarURL: externalUser["avatar_url"].(string),
        }, nil
    default:
        return nil, fmt.Errorf("unsupported provider: %s", providerID)
    }
}
```

## Frontend Integration

### React Example

```typescript
// Fetch available providers
const providers = await fetch('/auth/providers').then(r => r.json());

// Display login buttons
{providers.providers.map(provider => (
  <button 
    key={provider.id}
    onClick={() => window.location.href = `/auth/${provider.id}`}
  >
    <img src={provider.icon_url} alt={provider.display_name} />
    Login with {provider.display_name}
  </button>
))}
```

### Vue.js Example

```vue
<template>
  <div>
    <button 
      v-for="provider in providers" 
      :key="provider.id"
      @click="loginWith(provider.id)"
    >
      <img :src="provider.icon_url" :alt="provider.display_name" />
      Login with {{ provider.display_name }}
    </button>
  </div>
</template>

<script>
export default {
  data() {
    return { providers: [] }
  },
  async mounted() {
    const response = await fetch('/auth/providers');
    const data = await response.json();
    this.providers = data.providers;
  },
  methods: {
    loginWith(providerId) {
      window.location.href = `/auth/${providerId}`;
    }
  }
}
</script>
```

## Security Considerations

1. **CSRF Protection**: State parameter is used to prevent CSRF attacks
2. **Secure Cookies**: Authentication cookies are set with HttpOnly and Secure flags
3. **Token Validation**: JWT tokens are properly validated and have expiration times
4. **HTTPS Required**: Production deployments should use HTTPS
5. **Client Secret Security**: Store client secrets securely (environment variables, secrets management)

## Testing

Run the tests:

```bash
go test ./pkg/externalprovider/...
```

## Troubleshooting

### Common Issues

1. **Invalid Redirect URI**: Ensure callback URLs match exactly in provider configuration
2. **Client Secret Mismatch**: Verify client ID and secret are correct
3. **Scope Issues**: Check that requested scopes are enabled for your application
4. **CORS Errors**: Configure CORS properly for cross-origin requests

### Debug Logging

Enable debug logging to troubleshoot OAuth2 flows:

```go
import "log/slog"

// Set log level to debug
slog.SetLogLoggerLevel(slog.LevelDebug)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This package is part of Simple-IDM and follows the same license terms.
