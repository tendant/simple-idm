# Login Flow Package

## Overview

The `loginflow` package provides a simplified, type-safe login flow implementation for the Simple IDM system. It handles various authentication scenarios including password-based login, magic link validation, 2FA, device recognition, and multi-user selection.

**Key Features:**
- **Direct function calls** - No complex flow abstraction
- **Type-safe** - Compile-time error checking
- **Modular** - Optional features (2FA, device tracking) can use no-op implementations
- **Clear control flow** - Read authentication logic top-to-bottom
- **Easy to customize** - Copy and modify `Process*` methods for custom flows

## Architecture

### Core Components

**LoginFlowService** - Main service that orchestrates login flows
```go
type LoginFlowService struct {
    loginService     *login.LoginService
    twoFactorService twofa.TwoFactorService
    deviceService    *device.DeviceService
    tokenService     tg.TokenService
    userMapper       mapper.UserMapper
}
```

**Request** - Unified request structure for all login flows
```go
type Request struct {
    Username             string
    Password             string
    MagicLinkToken       string
    IPAddress            string
    UserAgent            string
    DeviceFingerprint    device.FingerprintData
    DeviceFingerprintStr string

    // Resumption fields (for multi-step flows)
    IsResumption   bool
    TempToken      string
    TwoFACode      string
    TwoFAType      string
    DeliveryOption string
    RememberDevice bool

    FlowType string // "web", "mobile", "email", "magic_link"
}
```

**Result** - Unified result structure
```go
type Result struct {
    Success                 bool
    RequiresTwoFA           bool
    RequiresUserSelection   bool
    RequiresUserAssociation bool
    Users                   []mapper.User
    LoginID                 uuid.UUID
    TwoFactorMethods        []TwoFactorMethod
    Tokens                  map[string]tg.TokenValue
    DeviceRecognized        bool
    ErrorResponse           *Error
}
```

## Usage

### Initialization

```go
import (
    "github.com/tendant/simple-idm/pkg/loginflow"
    "github.com/tendant/simple-idm/pkg/login"
    "github.com/tendant/simple-idm/pkg/twofa"
    "github.com/tendant/simple-idm/pkg/device"
    "github.com/tendant/simple-idm/pkg/mapper"
    tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Initialize all required services
loginService := login.NewLoginService(...)
tokenService := tg.NewTokenService(...)
userMapper := mapper.NewUserMapper(...)

// Optional: Use real 2FA service
twoFaService := twofa.NewTwoFaService(...)

// Optional: Use no-op 2FA service (skips 2FA)
// twoFaService := twofa.NewNoOpTwoFactorService()

// Optional: Use real device service
deviceRepository := device.NewPostgresDeviceRepository(...)
deviceService := device.NewDeviceService(deviceRepository, loginRepository)

// Optional: Use no-op device service (skips device tracking)
// deviceRepository := device.NewNoOpDeviceRepository()
// deviceService := device.NewDeviceService(deviceRepository, loginRepository)

// Create login flow service
loginFlowService := loginflow.NewLoginFlowService(
    loginService,
    twoFaService,
    deviceService,
    tokenService,
    nil, // tokenCookieService (not currently stored)
    userMapper,
)
```

### Basic Login Flows

#### 1. Web Login (Username/Password)
```go
result := loginFlowService.ProcessLogin(ctx, loginflow.Request{
    Username:             "user@example.com",
    Password:             "password123",
    IPAddress:            "192.168.1.1",
    UserAgent:            "Mozilla/5.0...",
    DeviceFingerprint:    fingerprintData,
    DeviceFingerprintStr: device.GenerateFingerprint(fingerprintData),
    FlowType:             "web",
})

if result.Success {
    // Login successful, tokens available in result.Tokens
    accessToken := result.Tokens["access_token"]
    refreshToken := result.Tokens["refresh_token"]
}

if result.RequiresTwoFA {
    // 2FA required, present 2FA methods to user
    methods := result.TwoFactorMethods
    tempToken := result.Tokens["temp_token"]
    // Prompt user for 2FA code, then call Process2FAValidation
}

if result.RequiresUserSelection {
    // Multiple users associated with login, present options
    users := result.Users
    tempToken := result.Tokens["temp_token"]
    // Prompt user to select, then call ProcessUserSwitch
}
```

#### 2. Mobile Login
```go
result := loginFlowService.ProcessMobileLogin(ctx, loginflow.Request{
    Username:             "user@example.com",
    Password:             "password123",
    DeviceFingerprint:    fingerprintData,
    DeviceFingerprintStr: device.GenerateFingerprint(fingerprintData),
    FlowType:             "mobile",
})
```

#### 3. Email-Based Login
```go
result := loginFlowService.ProcessLoginByEmail(
    ctx,
    "user@example.com",  // email
    "password123",        // password
    "192.168.1.1",       // ipAddress
    "Mozilla/5.0...",    // userAgent
    fingerprintData,     // device fingerprint
)
```

#### 4. Magic Link Validation
```go
result := loginFlowService.ProcessMagicLinkValidation(
    ctx,
    "magic-link-token",  // token from email link
    "192.168.1.1",       // ipAddress
    "Mozilla/5.0...",    // userAgent
    fingerprintData,     // device fingerprint
)
```

### Multi-Step Flows (Resumption)

#### 2FA Validation
```go
// After receiving temp token from initial login
result := loginFlowService.Process2FAValidation(ctx, loginflow.TwoFAValidationRequest{
    TokenString:          tempToken,
    TwoFAType:            "totp", // or "sms", "email"
    Passcode:             "123456",
    RememberDevice:       true, // Optional: remember this device
    IPAddress:            "192.168.1.1",
    UserAgent:            "Mozilla/5.0...",
    DeviceFingerprint:    fingerprintData,
    DeviceFingerprintStr: device.GenerateFingerprint(fingerprintData),
})
```

#### User Selection
```go
// After receiving temp token and user list from initial login
result := loginFlowService.ProcessUserSwitch(ctx, loginflow.UserSwitchRequest{
    TokenString:          tempToken,
    TargetUserID:         "selected-user-uuid",
    IPAddress:            "192.168.1.1",
    UserAgent:            "Mozilla/5.0...",
    DeviceFingerprint:    fingerprintData,
    DeviceFingerprintStr: device.GenerateFingerprint(fingerprintData),
})
```

#### 2FA Code Sending
```go
// Send 2FA code to user's email or phone
result := loginFlowService.Process2FASend(ctx, loginflow.TwoFASendRequest{
    TokenString:    tempToken,
    UserID:         "user-uuid",
    TwoFAType:      "sms", // or "email"
    DeliveryOption: "hashed-phone-or-email",
})
```

### Token Management

#### Refresh Tokens
```go
result := loginFlowService.ProcessTokenRefresh(ctx, loginflow.TokenRefreshRequest{
    RefreshToken: refreshToken,
})

// For mobile clients
result := loginFlowService.ProcessMobileTokenRefresh(ctx, loginflow.TokenRefreshRequest{
    RefreshToken: refreshToken,
})
```

#### Logout
```go
result := loginFlowService.ProcessLogout(ctx)
// Returns logout tokens with immediate expiry
```

## Authentication Flow Details

### Standard Login Flow

1. **Credential Authentication** - Validate username/password (or magic link)
2. **User Validation** - Ensure user account is active
3. **Device Recognition** - Check if device is recognized (skip if no fingerprint)
4. **2FA Requirement Check** - Skip if device is recognized or 2FA not enabled
   - If 2FA required: return `RequiresTwoFA=true` with temp token
5. **Multiple User Check** - If login has multiple associated users
   - If multiple users: return `RequiresUserSelection=true` with temp token
6. **Token Generation** - Create access/refresh tokens
7. **Success Recording** - Log successful login attempt

### 2FA Validation Flow

1. **Temp Token Validation** - Verify temp token from initial login
2. **2FA Code Validation** - Verify the provided passcode
3. **Device Remembering** - Optionally link device to login
4. **Multiple User Check** - Check if user selection needed
5. **Token Generation** - Create access/refresh tokens
6. **Success Recording** - Log successful login

### Magic Link Flow

1. **Magic Link Validation** - Validate token from email
2. **User Validation** - Ensure account is active
3. **Multiple User Check** - Skip device recognition and 2FA
4. **Token Generation** - Create tokens
5. **Success Recording** - Log successful login

## Customization

### Creating Custom Flows

You can customize authentication flows by:

1. **Copying and modifying Process* methods** - Create your own flow logic
2. **Using helper functions** - Reuse existing building blocks
3. **Implementing custom validation** - Add your own checks

Example: Custom login with additional verification
```go
func (s *LoginFlowService) ProcessCustomLogin(ctx context.Context, request Request) Result {
    // 1. Standard authentication
    loginResult, err := s.authenticateCredentials(ctx, request)
    if err != nil {
        return s.errorResult(ErrorTypeInvalidCredentials, err.Error())
    }

    // 2. Custom validation
    if err := s.myCustomValidation(ctx, loginResult); err != nil {
        return s.errorResult("custom_error", err.Error())
    }

    // 3. Standard user validation
    if err := s.validateUserAccount(ctx, loginResult, request); err != nil {
        return s.errorResult(ErrorTypeNoUserFound, "Account not active")
    }

    // 4. Skip device recognition and 2FA for your use case

    // 5. Generate tokens
    tokens, err := s.generateLoginTokensInternal(ctx, loginResult.Users[0], "web")
    if err != nil {
        return s.errorResult(ErrorTypeInternalError, "Failed to create tokens")
    }

    return s.successResult(tokens)
}
```

### Available Helper Functions

**Authentication:**
- `authenticateCredentials(ctx, req)` - Validate credentials (password, email, magic link)
- `validateUserAccount(ctx, loginResult, req)` - Check account is active
- `recordLoginAttempt(ctx, loginID, req, success, failureReason)` - Log attempt

**Device & 2FA:**
- `checkDeviceRecognition(ctx, loginID, fingerprintStr)` - Check if device recognized
- `check2FARequirement(ctx, loginID)` - Check if 2FA enabled
- `validate2FACode(ctx, loginID, twoFAType, passcode)` - Validate 2FA code
- `rememberDevice(ctx, loginID, fingerprintStr)` - Link device to login
- `send2FACode(ctx, loginID, userID, twoFAType, deliveryOption)` - Send 2FA code

**User Management:**
- `getMultipleUsers(ctx, loginID)` - Get all users for a login
- `hasMultipleUsers(ctx, loginID)` - Check if multiple users exist
- `getUserByID(ctx, userID)` - Get specific user
- `getUserFromLoginID(ctx, loginID)` - Get first user for login

**Tokens:**
- `generateLoginTokensInternal(ctx, user, tokenType)` - Create access/refresh tokens
- `generateTempTokenInternal(ctx, userID, extraClaims)` - Create temp token
- `validateTempTokenInternal(ctx, tokenString)` - Validate temp token

**Results:**
- `errorResult(errorType, message)` - Create error result
- `require2FAResult(loginID, methods, tempToken)` - Create 2FA required result
- `requireUserSelectionResult(loginID, users, tempToken)` - Create user selection result
- `successResult(tokens)` - Create success result

## Error Handling

### Error Types

```go
const (
    ErrorTypeAccountLocked      = "account_locked"
    ErrorTypePasswordExpired    = "password_expired"
    ErrorTypeInvalidCredentials = "invalid_credentials"
    ErrorTypeNoUserFound        = "no_user_found"
    ErrorTypeInternalError      = "internal_error"
)
```

### Checking Errors

```go
result := loginFlowService.ProcessLogin(ctx, request)

if !result.Success && result.ErrorResponse != nil {
    switch result.ErrorResponse.Type {
    case loginflow.ErrorTypeAccountLocked:
        // Account is temporarily locked
        message := result.ErrorResponse.Message // "Your account has been temporarily locked..."

    case loginflow.ErrorTypeInvalidCredentials:
        // Wrong username or password

    case loginflow.ErrorTypePasswordExpired:
        // Password needs reset

    case loginflow.ErrorTypeNoUserFound:
        // Account not active

    case loginflow.ErrorTypeInternalError:
        // System error
    }
}
```

## Optional Features

### No-Op Services

If you don't need certain features, use no-op implementations:

#### Disable 2FA
```go
twoFaService := twofa.NewNoOpTwoFactorService()
```
- All 2FA checks return "not enabled"
- No 2FA prompts
- No database tables needed

#### Disable Device Tracking
```go
deviceRepository := device.NewNoOpDeviceRepository()
deviceService := device.NewDeviceService(deviceRepository, loginRepository)
```
- Device recognition always returns false
- "Remember me" silently succeeds but doesn't persist
- No device tracking tables needed

### Progressive Enhancement

Start with minimal features and add as needed:

```go
// 1. Start minimal (password-only)
services := loginflow.NewLoginFlowService(
    loginService,
    twofa.NewNoOpTwoFactorService(),      // No 2FA
    device.NewDeviceService(device.NewNoOpDeviceRepository(), loginRepo), // No device tracking
    tokenService,
    nil,
    userMapper,
)

// 2. Add 2FA later
twoFaService := twofa.NewTwoFaService(twofaQueries, ...)
services = loginflow.NewLoginFlowService(
    loginService,
    twoFaService,  // Real 2FA
    deviceService,
    tokenService,
    nil,
    userMapper,
)

// 3. Add device tracking later
deviceRepo := device.NewPostgresDeviceRepository(pool, ...)
deviceService = device.NewDeviceService(deviceRepo, loginRepo)
```

## Migration from Old Flow System

### What Changed

**Removed:**
- FlowExecutor, FlowBuilder, StepRegistry (flow abstraction)
- 13 step implementations (CredentialAuthenticationStep, etc.)
- Flow builders (BuildWebLoginFlow, BuildMobileLoginFlow, etc.)
- ServiceDependencies wrapper

**Kept:**
- All public API methods (`Process*` methods) - **zero breaking changes**
- Request and Result structures
- Error types and handling

### Public API (Unchanged)

All these methods have the **exact same signatures**:
- `ProcessLogin(ctx, Request)`
- `ProcessMobileLogin(ctx, Request)`
- `ProcessLoginByEmail(...)`
- `ProcessMagicLinkValidation(...)`
- `Process2FAValidation(ctx, TwoFAValidationRequest)`
- `ProcessMobile2FAValidation(ctx, TwoFAValidationRequest)`
- `ProcessUserSwitch(ctx, UserSwitchRequest)`
- `ProcessMobileUserLookup(ctx, MobileUserLookupRequest)`
- `Process2FASend(ctx, TwoFASendRequest)`
- `ProcessTokenRefresh(ctx, TokenRefreshRequest)`
- `ProcessMobileTokenRefresh(ctx, TokenRefreshRequest)`
- `ProcessLogout(ctx)`

### Benefits of New Architecture

**Simpler:**
- ~600 lines of code removed
- No flow abstraction to learn
- Direct function calls

**More Maintainable:**
- Type-safe (no string-keyed maps)
- Clear control flow (read top-to-bottom)
- Easier debugging

**More Flexible:**
- Copy and modify `Process*` methods for custom flows
- Reuse helper functions as building blocks
- No need to understand step ordering or flow execution

## Testing

### Unit Testing Helper Functions

```go
func TestCheckDeviceRecognition(t *testing.T) {
    // Mock device service
    mockDevice := &MockDeviceService{}

    service := &LoginFlowService{
        deviceService: mockDevice,
    }

    result := service.checkDeviceRecognition(ctx, loginID, "fingerprint")

    assert.True(t, result)
}
```

### Integration Testing

The `service_test.go` file contains integration tests using testcontainers:

```bash
go test -v ./pkg/loginflow/...
```

## Examples

See the following implementations for complete examples:
- `cmd/loginv2/main.go` - Full-featured implementation with all services
- `cmd/quick/main.go` - Minimal implementation with no-op services

## Support

For issues, questions, or contributions, please refer to the main Simple IDM repository.
