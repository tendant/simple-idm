# Errors Package

Structured error handling with error codes for simple-idm.

## Overview

The `errors` package provides a standardized way to handle errors across all services with typed error codes, structured error details, and automatic HTTP status code mapping.

## Features

- **Structured Errors** - Type-safe error codes with message and details
- **40+ Error Codes** - Predefined codes for common scenarios
- **Error Wrapping** - Add context while preserving original errors
- **HTTP Mapping** - Automatic conversion to HTTP status codes
- **Error Inspection** - Check codes and extract details

## Quick Start

```go
import "github.com/tendant/simple-idm/pkg/errors"

// Create errors
err := errors.New(errors.ErrCodeUserNotFound, "user not found")
err := errors.Newf(errors.ErrCodeInvalidInput, "invalid email: %s", email)

// Use convenience constructors
err := errors.NotFound("user", userID)
err := errors.AlreadyExists("username", username)
err := errors.InvalidInput("email", "invalid format")

// Wrap errors
err := errors.Wrap(dbErr, errors.ErrCodeInternal, "database query failed")

// Add details
err := errors.NotFound("user", id).
    WithDetail("user_id", id).
    WithDetail("search_by", "email")

// Check error codes
if errors.IsCode(err, errors.ErrCodeUserNotFound) {
    // Handle not found
}

// Get HTTP status code
statusCode := err.HTTPStatusCode() // 404
```

## Error Codes

### Generic

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ErrCodeInternal` | 500 | Internal server error |
| `ErrCodeInvalidInput` | 400 | Invalid input data |
| `ErrCodeNotFound` | 404 | Resource not found |
| `ErrCodeAlreadyExists` | 409 | Resource already exists |
| `ErrCodeUnauthorized` | 401 | Unauthorized access |
| `ErrCodeForbidden` | 403 | Forbidden action |
| `ErrCodeConflict` | 409 | Conflict with current state |
| `ErrCodeTimeout` | 503 | Operation timed out |
| `ErrCodeRateLimitExceeded` | 429 | Too many requests |

### Authentication

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ErrCodeAuthFailed` | 401 | Authentication failed |
| `ErrCodeInvalidCredentials` | 401 | Invalid credentials |
| `ErrCodeTokenExpired` | 401 | Token expired |
| `ErrCodeTokenInvalid` | 401 | Invalid token |
| `ErrCodeSessionExpired` | 401 | Session expired |

### User/Account

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ErrCodeUserNotFound` | 404 | User not found |
| `ErrCodeUserAlreadyExists` | 409 | User already exists |
| `ErrCodeUserLocked` | 403 | User account locked |
| `ErrCodeUserDisabled` | 403 | User account disabled |
| `ErrCodeEmailNotVerified` | 403 | Email not verified |
| `ErrCodeEmailAlreadyVerified` | 409 | Email already verified |

### Password

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ErrCodePasswordComplexity` | 400 | Password doesn't meet requirements |
| `ErrCodePasswordExpired` | 403 | Password has expired |
| `ErrCodePasswordReused` | 409 | Password was recently used |

### 2FA

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ErrCode2FARequired` | 401 | Two-factor authentication required |
| `ErrCode2FAInvalid` | 401 | Invalid 2FA code |
| `ErrCode2FAExpired` | 401 | 2FA code expired |

### Validation

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ErrCodeValidationFailed` | 400 | Validation failed |
| `ErrCodeInvalidFormat` | 400 | Invalid format |
| `ErrCodeMissingRequired` | 400 | Required field missing |
| `ErrCodeValueTooLong` | 400 | Value exceeds max length |
| `ErrCodeValueTooShort` | 400 | Value below min length |
| `ErrCodeValueOutOfRange` | 400 | Value out of valid range |

See [errors.go](errors.go) for the complete list.

## API Reference

### Creating Errors

```go
// Basic constructors
New(code ErrorCode, message string) *Error
Newf(code ErrorCode, format string, args ...interface{}) *Error

// Wrapping errors
Wrap(err error, code ErrorCode, message string) *Error
Wrapf(err error, code ErrorCode, format string, args ...interface{}) *Error

// Convenience constructors
NotFound(resourceType, identifier string) *Error
AlreadyExists(resourceType, identifier string) *Error
InvalidInput(field, reason string) *Error
Unauthorized(message string) *Error
Forbidden(message string) *Error
Internal(message string) *Error
InternalWrap(err error, message string) *Error
ValidationFailed(details map[string]interface{}) *Error
RateLimitExceeded(retryAfter string) *Error
```

### Adding Details

```go
// Add single detail
err.WithDetail(key string, value interface{}) *Error

// Add multiple details
err.WithDetails(details map[string]interface{}) *Error
```

### Inspecting Errors

```go
// Check if error has specific code
IsCode(err error, code ErrorCode) bool

// Get error code
GetCode(err error) ErrorCode

// Get error details
GetDetails(err error) map[string]interface{}

// Get HTTP status code
err.HTTPStatusCode() int
```

## Examples

### Example 1: Service Layer

```go
type UserService struct {
    repo UserRepository
}

func (s *UserService) GetUser(ctx context.Context, id string) (*User, error) {
    user, err := s.repo.FindByID(ctx, id)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, errors.NotFound("user", id)
        }
        return nil, errors.InternalWrap(err, "failed to query user")
    }

    if user.Locked {
        return nil, errors.New(errors.ErrCodeUserLocked, "user account is locked").
            WithDetail("locked_until", user.LockedUntil)
    }

    return user, nil
}

func (s *UserService) CreateUser(ctx context.Context, email string) (*User, error) {
    if !isValidEmail(email) {
        return nil, errors.InvalidInput("email", "invalid format")
    }

    exists, err := s.repo.ExistsByEmail(ctx, email)
    if err != nil {
        return nil, errors.InternalWrap(err, "failed to check existence")
    }
    if exists {
        return nil, errors.AlreadyExists("user", email)
    }

    user, err := s.repo.Create(ctx, email)
    if err != nil {
        return nil, errors.InternalWrap(err, "failed to create user")
    }

    return user, nil
}
```

### Example 2: HTTP Handler

```go
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
    userID := chi.URLParam(r, "id")

    user, err := h.service.GetUser(r.Context(), userID)
    if err != nil {
        h.handleError(w, err)
        return
    }

    respondJSON(w, http.StatusOK, user)
}

func (h *UserHandler) handleError(w http.ResponseWriter, err error) {
    var structuredErr *errors.Error
    if !errors.As(err, &structuredErr) {
        log.Printf("Unstructured error: %v", err)
        respondJSON(w, http.StatusInternalServerError, map[string]string{
            "error": "Internal server error",
        })
        return
    }

    response := map[string]interface{}{
        "error": structuredErr.Message,
        "code":  structuredErr.Code,
    }

    if structuredErr.Details != nil {
        response["details"] = structuredErr.Details
    }

    statusCode := structuredErr.HTTPStatusCode()
    respondJSON(w, statusCode, response)
}
```

### Example 3: Validation

```go
func (s *UserService) ValidateUser(user *User) error {
    validationErrors := make(map[string]interface{})

    if user.Email == "" {
        validationErrors["email"] = "required"
    } else if !isValidEmail(user.Email) {
        validationErrors["email"] = "invalid format"
    }

    if len(user.Password) < 8 {
        validationErrors["password"] = map[string]interface{}{
            "error": "too short",
            "min_length": 8,
            "actual_length": len(user.Password),
        }
    }

    if len(validationErrors) > 0 {
        return errors.ValidationFailed(validationErrors)
    }

    return nil
}
```

### Example 4: Error Inspection

```go
func handleUserError(err error) {
    // Check specific error code
    if errors.IsCode(err, errors.ErrCodeUserNotFound) {
        log.Println("User not found - might need to create")
        return
    }

    // Get error code
    code := errors.GetCode(err)
    log.Printf("Error code: %s", code)

    // Get error details
    details := errors.GetDetails(err)
    if userID, ok := details["user_id"].(string); ok {
        log.Printf("Failed for user: %s", userID)
    }

    // Check HTTP status
    var structuredErr *errors.Error
    if errors.As(err, &structuredErr) {
        statusCode := structuredErr.HTTPStatusCode()
        if statusCode >= 500 {
            // Alert on server errors
            sendAlert(err)
        }
    }
}
```

## Migration Guide

### From Simple Errors

```go
// Before
var ErrUserNotFound = errors.New("user not found")

if notFound {
    return ErrUserNotFound
}

// After
if notFound {
    return errors.NotFound("user", userID)
}
```

### From fmt.Errorf

```go
// Before
return fmt.Errorf("failed to get user: %w", err)

// After
return errors.Wrap(err, errors.ErrCodeInternal, "failed to get user")
```

### From Custom Error Types

```go
// Before
type UserNotFoundError struct {
    UserID string
}

func (e *UserNotFoundError) Error() string {
    return fmt.Sprintf("user not found: %s", e.UserID)
}

// After
func notFoundError(userID string) error {
    return errors.NotFound("user", userID).
        WithDetail("user_id", userID)
}
```

## Best Practices

1. **Use Specific Codes**
   - Choose the most specific error code
   - Don't overuse `ErrCodeInternal`

2. **Add Context**
   - Include identifiers in details
   - Add helpful debugging information
   - Don't include sensitive data

3. **Wrap at Boundaries**
   - Wrap database errors at repository layer
   - Wrap external service errors at integration layer

4. **Handle at Right Level**
   - Create structured errors in service layer
   - Convert to HTTP in handler layer
   - Don't log same error multiple times

5. **Use Convenience Functions**
   - `NotFound()` instead of `New(ErrCodeNotFound, ...)`
   - `AlreadyExists()` for conflicts
   - `InvalidInput()` for validation

## Testing

```go
func TestGetUser_NotFound(t *testing.T) {
    service := setupTest(t)

    _, err := service.GetUser(ctx, "unknown-id")

    assert.Error(t, err)
    assert.True(t, errors.IsCode(err, errors.ErrCodeUserNotFound))

    var structuredErr *errors.Error
    if assert.True(t, errors.As(err, &structuredErr)) {
        assert.Equal(t, errors.ErrCodeUserNotFound, structuredErr.Code)
        assert.Equal(t, http.StatusNotFound, structuredErr.HTTPStatusCode())
    }
}
```

---

For complete documentation and examples, see [doc.go](doc.go).
