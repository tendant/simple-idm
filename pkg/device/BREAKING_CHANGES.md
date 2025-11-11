# Breaking Changes - device Package

## 2025-11: Removed Circular Dependency with login Package

### Summary

Removed the unused `loginRepository` parameter from `DeviceService` constructor. This eliminates an unnecessary circular dependency between the `device` and `login` packages, making both packages easier to use independently.

### What Changed

**Before (OLD):**
```go
import (
    "github.com/tendant/simple-idm/pkg/device"
    "github.com/tendant/simple-idm/pkg/login"
)

loginRepo := login.NewPostgresLoginRepository(loginQueries)
deviceRepo := device.NewPostgresDeviceRepository(pool)

// Old constructor required loginRepository
deviceService := device.NewDeviceService(deviceRepo, loginRepo)
```

**After (NEW):**
```go
import "github.com/tendant/simple-idm/pkg/device"

deviceRepo := device.NewPostgresDeviceRepository(pool)

// New constructor - no login dependency needed
deviceService := device.NewDeviceService(deviceRepo)
```

### Why This Change Was Made

1. **Unused Dependency**: The `loginRepository` field was declared in `DeviceService` but was never actually used in the implementation. This was dead code.

2. **Circular Dependency**: The `device` package imported `login` package, while `login/loginapi` imported `device` package, creating unnecessary coupling.

3. **Improved Reusability**: Both packages can now be used independently without importing the other, making them more modular and reusable.

### Migration Guide

#### For Simple Applications

If you're creating a `DeviceService`, simply remove the second parameter:

```go
// Before
deviceService := device.NewDeviceService(deviceRepo, loginRepo)

// After
deviceService := device.NewDeviceService(deviceRepo)
```

#### For Applications Using Options

If you're using functional options, the change is identical:

```go
// Before
deviceService := device.NewDeviceService(
    deviceRepo,
    loginRepo,
    device.WithDeviceExpirationDays(90*24*time.Hour),
)

// After
deviceService := device.NewDeviceService(
    deviceRepo,
    device.WithDeviceExpirationDays(90*24*time.Hour),
)
```

#### For Test Code

Update test setup functions:

```go
// Before
func setupTest(t *testing.T) *device.DeviceService {
    deviceRepo := device.NewInMemDeviceRepository()
    loginRepo := login.NewInMemoryLoginRepository()
    return device.NewDeviceService(deviceRepo, loginRepo)
}

// After
func setupTest(t *testing.T) *device.DeviceService {
    deviceRepo := device.NewInMemDeviceRepository()
    return device.NewDeviceService(deviceRepo)
}
```

### FAQs

**Q: Did the DeviceService functionality change?**
A: No. The service works exactly the same way. Only the constructor signature changed by removing an unused parameter.

**Q: Do I need to change how I use DeviceService methods?**
A: No. All methods (`RegisterDevice`, `LinkDeviceToLogin`, `FindDevicesByLogin`, etc.) work identically.

**Q: Why was loginRepository in the constructor if it wasn't used?**
A: It was likely a leftover from an earlier refactoring where the dependency was removed from the implementation but not from the constructor.

**Q: Will this break my existing code?**
A: Yes, this is a breaking change. You'll need to remove the `loginRepository` parameter when creating `DeviceService` instances. The fix is simple and quick.

**Q: What if I still need both device and login services?**
A: You can still use both services together. They just don't depend on each other anymore:

```go
// Both services can be created independently
deviceService := device.NewDeviceService(deviceRepo)
loginService := login.NewLoginServiceWithConfig(loginRepo, config)

// And used together in higher-level services like loginflow
loginFlowService := loginflow.NewLoginFlowService(
    loginService,
    twoFaService,
    deviceService,  // Still works fine
    tokenService,
    cookieService,
    userMapper,
)
```

### Benefits

1. **No Circular Dependencies**: Clean package structure with uni-directional imports
2. **Easier Testing**: Can test device package without importing login
3. **Better Modularity**: Each package has clear, minimal dependencies
4. **Reduced Coupling**: Changes to login package won't affect device package
5. **Simpler API**: One less parameter to worry about

### Affected Files

The following files were updated in this change:

- `pkg/device/service.go` - Removed loginRepository field and parameter
- `pkg/device/service_test.go` - Updated tests
- `cmd/quick/main.go` - Updated DeviceService creation
- `cmd/loginv2/main.go` - Updated DeviceService creation
- `cmd/login/main.go` - Updated DeviceService creation
- `cmd/passwordless-auth/main.go` - Updated DeviceService creation

### Verification

To verify your code works after the migration:

```bash
# Run device package tests
go test ./pkg/device/...

# Run integration tests
go test ./cmd/quick/...
go test ./cmd/loginv2/...

# Build all commands
go build ./cmd/...
```

All tests should pass without any functional changes.

### Related Changes

This is part of Phase 2 of the simple-idm refactoring effort to make packages more reusable as standalone libraries. See `REFACTORING_PLAN.md` for the full plan.

### Need Help?

If you encounter issues during migration:
1. Check that you've removed the `loginRepository` parameter from all `NewDeviceService` calls
2. Verify imports are correct (no need to import `login` package unless you're actually using it)
3. Run tests to ensure everything still works

For questions or issues, please file an issue in the repository.
