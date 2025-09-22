# External Provider Integration Guide

This document provides a complete guide for integrating external OAuth2 identity providers (Google, Microsoft, GitHub, LinkedIn) with simple-idm.

## Overview

The external provider system allows users to authenticate using third-party OAuth2 providers instead of traditional username/password authentication. This provides a seamless single sign-on (SSO) experience.

## Architecture

```
Frontend (Login Page) → External Provider API → OAuth2 Provider → User Authentication → JWT Token → Frontend Redirect
```

## Implementation Status

✅ **Backend Integration Complete**
- External provider service and repository
- OAuth2 flow implementation with CSRF protection
- API endpoints for provider listing and authentication
- Integration with existing login system
- Environment-based provider configuration

✅ **Frontend Integration Complete**
- TypeScript API client for external providers
- Updated Login page with provider buttons
- OAuth2 callback handling
- Error handling and user feedback

## Setup Instructions

### 1. Backend Configuration

The backend is already integrated in `cmd/login/main.go`. The system supports the following environment variables:

```bash
# Google OAuth2
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_ENABLED=true

# Microsoft OAuth2
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_ENABLED=true

# GitHub OAuth2
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_ENABLED=true

# LinkedIn OAuth2
LINKEDIN_CLIENT_ID=your-linkedin-client-id
LINKEDIN_CLIENT_SECRET=your-linkedin-client-secret
LINKEDIN_ENABLED=true
```

### 2. Provider Setup

#### Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API or Google Identity API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Set application type to "Web application"
6. Add authorized redirect URI: `http://localhost:4000/auth/google/callback`
7. Copy the Client ID and Client Secret

#### Microsoft OAuth2 Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" → "App registrations"
3. Click "New registration"
4. Set redirect URI: `http://localhost:4000/auth/microsoft/callback`
5. Go to "Certificates & secrets" → "New client secret"
6. Copy the Application (client) ID and client secret value

#### GitHub OAuth2 Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/applications/new)
2. Create a new OAuth App
3. Set Authorization callback URL: `http://localhost:4000/auth/github/callback`
4. Copy the Client ID and generate a Client Secret

#### LinkedIn OAuth2 Setup

1. Go to [LinkedIn Developer Portal](https://www.linkedin.com/developers/apps)
2. Create a new app
3. Add redirect URL: `http://localhost:4000/auth/github/callback`
4. Copy the Client ID and Client Secret

### 3. Running the System

1. Set the environment variables for your desired providers
2. Start the backend server:
   ```bash
   cd simple-idm/cmd/login
   go run main.go
   ```
3. Start the frontend:
   ```bash
   cd simple-idm/frontend
   npm run dev
   ```

## API Endpoints

### GET /api/idm/external/providers
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

### GET /api/idm/external/{provider}
Initiates OAuth2 flow for the specified provider.

**Parameters:**
- `provider` (path): Provider ID (e.g., "google", "microsoft")
- `redirect_url` (query, optional): URL to redirect after successful authentication

**Response:** HTTP 302 redirect to provider's OAuth2 authorization URL

### GET /api/idm/external/{provider}/callback
Handles OAuth2 callback from the provider.

**Parameters:**
- `provider` (path): Provider ID
- `code` (query): Authorization code from provider
- `state` (query): CSRF protection state parameter
- `error` (query, optional): Error code if authentication failed

**Response:** HTTP 302 redirect to frontend with authentication result

## Frontend Integration

### Login Page Features

The updated Login page (`frontend/src/pages/Login.tsx`) now includes:

1. **External Provider Buttons**: Dynamically loaded based on enabled providers
2. **OAuth2 Callback Handling**: Automatic detection and handling of authentication results
3. **Error Display**: User-friendly error messages for failed authentication
4. **Success Messages**: Confirmation of successful authentication with auto-redirect

### API Client

The TypeScript API client (`frontend/src/api/externalProviders.ts`) provides:

- `getExternalProviders()`: Fetch available providers
- `initiateOAuth2Flow()`: Start OAuth2 authentication
- `handleOAuth2Callback()`: Process authentication results
- `isOAuth2Callback()`: Check for callback parameters
- `hasOAuth2Error()`: Check for error parameters

## User Flow

1. **User visits login page**: Sees traditional login form + external provider buttons
2. **User clicks provider button**: Redirected to provider's OAuth2 authorization page
3. **User authenticates with provider**: Grants permission to access basic profile info
4. **Provider redirects back**: User returns to simple-idm with authorization code
5. **Backend processes callback**: Exchanges code for access token, fetches user info
6. **User mapping**: External user data mapped to internal user account
7. **JWT token generation**: User receives authentication token and session cookies
8. **Frontend redirect**: User redirected to intended destination or dashboard

## Security Features

- **CSRF Protection**: State parameter prevents cross-site request forgery
- **Secure Cookies**: HttpOnly and Secure flags for session cookies
- **Token Validation**: JWT tokens with proper expiration and validation
- **HTTPS Enforcement**: Production deployments should use HTTPS
- **Client Secret Security**: Secrets stored as environment variables

## Troubleshooting

### Common Issues

1. **"Invalid redirect URI"**
   - Ensure callback URLs match exactly in provider configuration
   - Check for trailing slashes or protocol mismatches

2. **"Client authentication failed"**
   - Verify client ID and secret are correct
   - Check environment variables are properly set

3. **"Insufficient scope"**
   - Ensure required scopes are enabled in provider app configuration
   - Check API permissions in provider console

4. **CORS errors**
   - Configure CORS properly for cross-origin requests
   - Ensure frontend and backend URLs are correctly configured

### Debug Logging

Enable debug logging to troubleshoot OAuth2 flows:

```go
import "log/slog"

// Set log level to debug
slog.SetLogLoggerLevel(slog.LevelDebug)
```

### Testing

Test the integration:

1. **Provider Configuration**: Verify providers appear on login page
2. **OAuth2 Flow**: Test authentication with each enabled provider
3. **Error Handling**: Test with invalid credentials or cancelled authentication
4. **User Mapping**: Verify user data is correctly mapped to internal accounts
5. **Session Management**: Test token generation and cookie handling

## Production Considerations

1. **HTTPS Required**: All OAuth2 flows must use HTTPS in production
2. **Environment Variables**: Use secure secret management for client secrets
3. **Rate Limiting**: Implement rate limiting for authentication endpoints
4. **Monitoring**: Monitor authentication success/failure rates
5. **User Privacy**: Ensure compliance with privacy regulations (GDPR, CCPA)

## Extending the System

### Adding New Providers

To add a new OAuth2 provider:

1. **Add configuration** to `ExternalProviderConfig` struct
2. **Update setup function** in `setupExternalProviders()`
3. **Configure provider** with appropriate URLs and scopes
4. **Test integration** with provider's OAuth2 implementation

### Custom User Mapping

Implement custom user mapping logic:

```go
func (m *CustomUserMapper) MapExternalUser(providerID string, externalUser map[string]interface{}) (*User, error) {
    switch providerID {
    case "custom-provider":
        return &User{
            Email:     externalUser["email"].(string),
            FirstName: externalUser["given_name"].(string),
            LastName:  externalUser["family_name"].(string),
            // Custom mapping logic
        }, nil
    default:
        return m.defaultMapper.MapExternalUser(providerID, externalUser)
    }
}
```

## Files Modified/Created

### Backend Files
- `pkg/externalprovider/` - Complete external provider package
- `cmd/login/main.go` - Integration with main application
- `pkg/externalprovider/api/` - HTTP API endpoints

### Frontend Files
- `frontend/src/api/externalProviders.ts` - TypeScript API client
- `frontend/src/pages/Login.tsx` - Updated login page with provider buttons

### Documentation
- `pkg/externalprovider/README.md` - Detailed package documentation
- `EXTERNAL_PROVIDER_INTEGRATION.md` - This integration guide

The external provider system is now fully integrated and ready for use with simple-idm!
