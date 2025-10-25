# Library Simplification - Optional Features

## Overview

We've made the Simple IDM library truly modular by making optional features like 2FA and device tracking completely opt-in. If you don't need a feature, you no longer have to initialize or configure it.

## Changes Made

### 1. **No-Op Service Implementations**

Created no-op implementations that can be used when features aren't needed:

- **`pkg/twofa/noop.go`** - NoOpTwoFactorService
  - Implements the `TwoFactorService` interface
  - All methods return errors or empty results
  - `FindEnabledTwoFAs()` returns empty slice (automatically skips 2FA)

- **`pkg/device/noop.go`** - NoOpDeviceRepository + NoOpDeviceService
  - Implements the `DeviceRepository` interface
  - All link/unlink operations silently succeed
  - Lookup methods return "not found" errors (handled gracefully by loginflow)

### 2. **LoginFlow Already Gracefully Handles No-Ops**

The existing loginflow steps were already well-designed to handle service failures:

- **DeviceRecognitionStep**: Errors → sets `DeviceRecognized=false` → continues
- **TwoFARequirementStep**: `FindEnabledTwoFAs()` returns `[]` → skips 2FA
- **SuccessRecordingStep**: `UpdateDeviceLastLogin()` error → logs but continues
- **DeviceRememberingStep**: `LinkDeviceToLogin()` error → logs but continues

**No changes needed to loginflow steps!** The error handling was already perfect.

### 3. **Updated cmd/quick for Minimal Dependencies**

**Before:**
```go
// Had to initialize even if unused:
twofaQueries := twofadb.New(pool)          // Database query layer
twoFaService := twofa.NewTwoFaService(...) // Full service
deviceRepository := device.NewPostgresDeviceRepositoryWithOptions(pool, ...)
deviceService := device.NewDeviceService(...)
loginFlowService := loginflow.New(login, twofa, device, ...)
```

**After:**
```go
// Only initialize what you need:
twoFaService := twofa.NewNoOpTwoFactorService()       // No database needed
deviceRepository := device.NewNoOpDeviceRepository()  // No database needed
deviceService := device.NewDeviceService(deviceRepository, loginRepository)
loginFlowService := loginflow.New(login, twofa, device, ...)
```

**Removed dependencies:**
- ❌ `pkg/twofa/twofadb` - no longer imported
- ❌ Database initialization for twofa tables
- ❌ Database initialization for device tables
- ❌ Complex configuration for device expiration

### 4. **Enhanced Documentation**

Updated `pkg/loginflow/service.go` to document which services are required vs optional:

```go
// NewLoginFlowService creates a new login flow service.
//
// Required services:
//   - loginService: handles authentication logic
//   - tokenService: generates JWT tokens
//   - tokenCookieService: manages token cookies
//   - userMapper: maps between user types
//
// Optional services (can use no-op implementations):
//   - twoFactorService: use twofa.NewNoOpTwoFactorService() if 2FA not needed
//   - deviceService: use device.NewNoOpDeviceService() if device tracking not needed
//
// When using no-op services, related flow steps will be automatically skipped.
```

## Benefits

### For Developers Using the Library

**Minimal Setup (cmd/quick):**
```go
// Only these services needed:
✓ loginService       (required)
✓ tokenService       (required)
✓ userMapper         (required)
✓ iamService         (required)
✓ roleService        (required)

// Optional (use no-ops):
○ twoFaService       (no-op)
○ deviceService      (no-op with no-op repo)
```

**Full Setup (cmd/loginv2):**
- Everything initialized as before
- No breaking changes
- All features available

**Progressive Enhancement:**
```go
// Start minimal
services := quickidm.New(config)

// Add 2FA later when needed
twoFaService := twofa.NewTwoFaService(twofaQueries, ...)
loginFlowService = loginflow.New(login, twoFaService, device, ...)

// Add device tracking later when needed
deviceRepo := device.NewPostgresDeviceRepository(pool, ...)
deviceService := device.NewDeviceService(deviceRepo, loginRepo)
```

### Complexity Reduction

**Database Tables:**
- No 2FA → don't need `two_factor_auth` table
- No device tracking → don't need `devices`, `login_devices` tables

**Configuration:**
- No 2FA → don't need TOTP/SMS settings
- No device tracking → don't need expiration settings

**Dependencies:**
- No 2FA → don't need twilio, otp libraries (compile-time)
- No device tracking → less database queries at runtime

## Example: cmd/quick Simplification

**Lines of Code Reduction:**
- Before: ~650 lines
- After: ~600 lines (50 lines removed)

**Initialization Complexity:**
- Before: Initialize 7 database query layers
- After: Initialize 5 database query layers (2FA and device tables not needed)

**Services Initialized:**
- Before: 12 services (all required)
- After: 10 services (2 are no-ops, don't need real initialization)

## Usage Patterns

### Pattern 1: No 2FA, No Device Tracking (cmd/quick)
```go
twoFaService := twofa.NewNoOpTwoFactorService()
deviceRepo := device.NewNoOpDeviceRepository()
deviceService := device.NewDeviceService(deviceRepo, loginRepo)

loginFlowService := loginflow.NewLoginFlowService(
    loginService,
    twoFaService,    // no-op
    deviceService,   // no-op
    tokenService,
    cookieService,
    userMapper,
)
```

**Result:** Password + magic link auth only, no 2FA prompts, no device tracking

### Pattern 2: With 2FA, No Device Tracking
```go
twofaQueries := twofadb.New(pool)
twoFaService := twofa.NewTwoFaService(twofaQueries, ...)

deviceRepo := device.NewNoOpDeviceRepository()
deviceService := device.NewDeviceService(deviceRepo, loginRepo)

loginFlowService := loginflow.NewLoginFlowService(
    loginService,
    twoFaService,    // real 2FA
    deviceService,   // no-op
    tokenService,
    cookieService,
    userMapper,
)
```

**Result:** 2FA enabled, but devices aren't tracked/remembered

### Pattern 3: Full Features (cmd/loginv2)
```go
twofaQueries := twofadb.New(pool)
twoFaService := twofa.NewTwoFaService(twofaQueries, ...)

deviceRepo := device.NewPostgresDeviceRepositoryWithOptions(pool, opts)
deviceService := device.NewDeviceService(deviceRepo, loginRepo)

loginFlowService := loginflow.NewLoginFlowService(
    loginService,
    twoFaService,    // real 2FA
    deviceService,   // real device tracking
    tokenService,
    cookieService,
    userMapper,
)
```

**Result:** All features enabled (2FA + device tracking/"remember me")

## Migration Guide

### Existing Applications (No Changes Required)

If you're already using the library with full features (like cmd/loginv2), **no changes are required**. Everything continues to work as before.

### New Applications (Recommended Approach)

1. **Start Minimal**: Use cmd/quick as a template
2. **Add Features Progressively**: As your needs grow, swap no-op services for real ones
3. **No Refactoring Needed**: The API stays the same whether using no-op or real services

## Technical Details

### Why No-Op Instead of Nil?

**Considered approaches:**
1. ✗ Allow nil services → requires nil checks everywhere
2. ✗ Make services interfaces → big refactor, breaking change
3. ✓ **No-op implementations** → no nil checks, no breaking changes

**Chosen approach:**
- No-op services implement the same interface/contract
- Existing error handling works perfectly
- No changes to loginflow or other consumers
- Type-safe (compiler catches missing methods)

### Flow Behavior with No-Ops

**2FA Flow:**
1. `TwoFARequirementStep` calls `FindEnabledTwoFAs()`
2. No-op returns `[]` (empty slice)
3. Step sees no 2FA methods → skips 2FA
4. User logs in directly ✓

**Device Tracking Flow:**
1. `DeviceRecognitionStep` calls `FindLoginDeviceByFingerprintAndLoginID()`
2. No-op returns error "device not found"
3. Step handles error → sets `DeviceRecognized = false`
4. Flow continues normally (may prompt for 2FA if enabled) ✓

## Future Enhancements

### Make OIDC Optional
Currently OIDC services are always initialized. Could make optional:

```go
type Config struct {
    EnableOIDC bool `env:"ENABLE_OIDC" env-default:"true"`
}

if config.EnableOIDC {
    oauth2ClientService = ...
    oidcService = ...
}
```

### Make Email Verification Optional
Currently always initialized. Could make optional:

```go
type Config struct {
    EnableEmailVerification bool `env:"ENABLE_EMAIL_VERIFICATION" env-default:"true"`
}
```

### Plugin Architecture
Further enhancement: Load features as plugins

```go
idm := quickidm.New(config)
idm.EnableFeature(twofa.Plugin{...})
idm.EnableFeature(device.Plugin{...})
```

## Conclusion

The library is now **truly modular**:
- ✓ Optional features don't require initialization
- ✓ No database tables needed for unused features
- ✓ No configuration needed for unused features
- ✓ Clean, simple code for minimal setups
- ✓ Full power available when needed
- ✓ No breaking changes to existing code
- ✓ Type-safe with compiler checks

**Philosophy**: Pay only for what you use, but keep the door open for future expansion.
