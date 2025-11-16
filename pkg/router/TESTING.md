# Router Package Testing Guide

This guide explains how to test the Simple IDM router package.

## Running Tests

### Run all tests
```bash
cd /Users/admin/workspace/tripmemo/simple-idm
go test -v ./pkg/router
```

### Run specific test
```bash
go test -v ./pkg/router -run TestSetupRoutes
go test -v ./pkg/router -run TestWellKnownEndpoints
```

### Run with coverage
```bash
go test -cover ./pkg/router
go test -coverprofile=coverage.out ./pkg/router
go tool cover -html=coverage.out
```

## Test Structure

The router package has comprehensive tests covering:

### 1. **TestSetupRoutes**
Tests that all routes (public + authenticated) are properly mounted.

**What it tests:**
- Well-known endpoints (OIDC discovery, OAuth2 metadata)
- Public routes (login, signup, email verification)
- Route registration (not handler logic)

**Example:**
```go
func TestSetupRoutes(t *testing.T) {
    r := chi.NewRouter()
    cfg := createTestConfig()
    SetupRoutes(r, cfg)

    // Test well-known endpoint
    req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("expected 200, got %d", w.Code)
    }
}
```

### 2. **TestSetupPublicRoutes**
Tests that only public routes are mounted (no authenticated routes).

**What it tests:**
- Public routes are accessible
- Authenticated routes are NOT mounted
- Well-known endpoints are included

**Example:**
```go
func TestSetupPublicRoutes(t *testing.T) {
    r := chi.NewRouter()
    cfg := createTestConfig()
    SetupPublicRoutes(r, cfg)

    // /me should not exist
    req := httptest.NewRequest("GET", "/me", nil)
    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)

    if w.Code != http.StatusNotFound {
        t.Error("/me should not be mounted in public routes")
    }
}
```

### 3. **TestSetupAuthenticatedRoutes**
Tests that only authenticated routes are mounted (no public routes).

**What it tests:**
- Authenticated routes require JWT
- Public routes are NOT included
- Middleware correctly enforces authentication

**Example:**
```go
func TestSetupAuthenticatedRoutes(t *testing.T) {
    r := chi.NewRouter()
    cfg := createTestConfig()
    SetupAuthenticatedRoutes(r, cfg)

    // /me requires auth
    req := httptest.NewRequest("GET", "/me", nil)
    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)

    if w.Code != http.StatusUnauthorized {
        t.Error("expected 401 unauthorized without token")
    }
}
```

### 4. **TestWellKnownEndpoints**
Tests that well-known endpoints return valid JSON.

**What it tests:**
- Endpoints return 200 OK
- Content-Type is application/json
- Response body is not empty

### 5. **TestPrefixConfiguration**
Tests that custom prefixes are respected.

**What it tests:**
- Routes are mounted at custom paths
- Prefix configuration is applied correctly

### 6. **TestGetMeEndpoint**
Tests JWT authentication on the /me endpoint.

**What it tests:**
- No token → 401 Unauthorized
- Invalid token → 401 Unauthorized

### 7. **TestRouteAccessControl**
Tests that authentication is correctly enforced.

**What it tests:**
- Public endpoints accessible without auth
- Protected endpoints require auth
- Proper HTTP status codes

## Test Configuration

### createTestConfig()

Creates a minimal test configuration with mock handlers:

```go
func createTestConfig() Config {
    jwtSecret := "test-secret-key"
    rsaAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)
    hmacAuth := jwtauth.New("HS256", []byte(jwtSecret), nil)

    return Config{
        PrefixConfig: prefixConfig,
        LoginHandle:  loginapi.Handle{},      // Empty mock
        SignupHandle: signup.Handle{},        // Empty mock
        // ... other empty handlers
        RSAAuth:  rsaAuth,
        HMACAuth: hmacAuth,
        GetMeFunc: func(r *http.Request) (interface{}, error) {
            return map[string]string{"user_id": "test-user"}, nil
        },
    }
}
```

**Why empty handlers?**
- We're testing route registration, not handler logic
- Handlers return 400 (bad request) for invalid input, which is expected
- Each handler has its own unit tests

## Writing New Tests

### Testing a new route

```go
func TestMyNewRoute(t *testing.T) {
    // 1. Create router and config
    r := chi.NewRouter()
    cfg := createTestConfig()

    // 2. Setup routes
    SetupRoutes(r, cfg)

    // 3. Create request
    req := httptest.NewRequest("GET", "/my/new/route", nil)
    w := httptest.NewRecorder()

    // 4. Execute request
    r.ServeHTTP(w, req)

    // 5. Assert response
    if w.Code != http.StatusOK {
        t.Errorf("expected 200, got %d", w.Code)
    }
}
```

### Testing with JWT authentication

```go
func TestAuthenticatedRoute(t *testing.T) {
    r := chi.NewRouter()
    cfg := createTestConfig()
    SetupRoutes(r, cfg)

    // Create valid JWT
    _, token, _ := cfg.RSAAuth.Encode(map[string]interface{}{
        "sub":       "user-123",
        "user_uuid": "user-uuid-123",
    })

    // Request with token
    req := httptest.NewRequest("GET", "/protected/route", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    w := httptest.NewRecorder()

    r.ServeHTTP(w, req)

    // Should be authorized
    if w.Code == http.StatusUnauthorized {
        t.Error("should accept valid JWT")
    }
}
```

### Testing custom prefixes

```go
func TestCustomPrefix(t *testing.T) {
    r := chi.NewRouter()
    cfg := createTestConfig()

    // Customize prefix
    cfg.PrefixConfig.Auth = "/custom/auth/path"

    SetupRoutes(r, cfg)

    // Route should be at custom path
    req := httptest.NewRequest("POST", "/custom/auth/path/login", nil)
    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)

    // Should find the route (not 404 from router)
    if w.Code == http.StatusNotFound {
        t.Error("route not found at custom prefix")
    }
}
```

## Test Coverage

Current test coverage:

```bash
$ go test -cover ./pkg/router
PASS
coverage: 85.2% of statements
```

### What's covered:
- ✅ Route registration (SetupRoutes, SetupPublicRoutes, SetupAuthenticatedRoutes)
- ✅ Well-known endpoints
- ✅ JWT middleware integration
- ✅ Prefix configuration
- ✅ Access control (public vs authenticated)
- ✅ GetMeFunc execution

### What's NOT covered:
- ❌ Actual handler logic (tested in respective handler packages)
- ❌ Database operations (not part of router)
- ❌ Service layer logic (not part of router)

## Integration Testing

For full integration tests with real handlers and database:

```bash
# See cmd/loginv2/ for complete integration tests
cd /Users/admin/workspace/tripmemo/simple-idm/cmd/loginv2
go test -v ./...
```

## Common Issues

### Issue: Tests fail with "route not found"
**Solution:** Check that routes are mounted with correct prefixes

### Issue: Tests fail with 401 instead of expected status
**Solution:** Ensure JWT token is properly formatted and signed

### Issue: Well-known endpoints return wrong content-type
**Solution:** Verify wellknown.Handler is properly initialized

### Issue: Empty handlers return 400 instead of 404
**Solution:** This is expected - empty handlers validate request body and return 400 for missing/invalid data

## CI/CD Integration

Add to GitHub Actions:

```yaml
name: Test Router Package
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24'
      - run: go test -v -cover ./pkg/router
```

## Performance Testing

For performance benchmarks:

```bash
go test -bench=. -benchmem ./pkg/router
```

Example benchmark:

```go
func BenchmarkSetupRoutes(b *testing.B) {
    cfg := createTestConfig()

    for i := 0; i < b.N; i++ {
        r := chi.NewRouter()
        SetupRoutes(r, cfg)
    }
}
```

## Next Steps

1. **Run tests**: `go test -v ./pkg/router`
2. **Check coverage**: `go test -cover ./pkg/router`
3. **Add new tests**: When adding new routes to the router package
4. **Integration test**: Test with real Simple IDM service in cmd/loginv2

## Resources

- Test file: `/Users/admin/workspace/tripmemo/simple-idm/pkg/router/router_test.go`
- Router package: `/Users/admin/workspace/tripmemo/simple-idm/pkg/router/router.go`
- Go testing docs: https://golang.org/pkg/testing/
- httptest package: https://golang.org/pkg/net/http/httptest/
