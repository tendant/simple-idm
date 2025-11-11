package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode represents a unique error code
type ErrorCode string

// Common error codes used across all packages
const (
	// Generic errors
	ErrCodeInternal       ErrorCode = "INTERNAL_ERROR"
	ErrCodeInvalidInput   ErrorCode = "INVALID_INPUT"
	ErrCodeNotFound       ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists  ErrorCode = "ALREADY_EXISTS"
	ErrCodeUnauthorized   ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden      ErrorCode = "FORBIDDEN"
	ErrCodeConflict       ErrorCode = "CONFLICT"
	ErrCodeTimeout        ErrorCode = "TIMEOUT"
	ErrCodeRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"

	// Authentication errors
	ErrCodeAuthFailed         ErrorCode = "AUTH_FAILED"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenInvalid       ErrorCode = "TOKEN_INVALID"
	ErrCodeSessionExpired     ErrorCode = "SESSION_EXPIRED"

	// User/Account errors
	ErrCodeUserNotFound       ErrorCode = "USER_NOT_FOUND"
	ErrCodeUserAlreadyExists  ErrorCode = "USER_ALREADY_EXISTS"
	ErrCodeUserLocked         ErrorCode = "USER_LOCKED"
	ErrCodeUserDisabled       ErrorCode = "USER_DISABLED"
	ErrCodeEmailNotVerified   ErrorCode = "EMAIL_NOT_VERIFIED"
	ErrCodeEmailAlreadyVerified ErrorCode = "EMAIL_ALREADY_VERIFIED"

	// Password errors
	ErrCodePasswordComplexity ErrorCode = "PASSWORD_COMPLEXITY"
	ErrCodePasswordExpired    ErrorCode = "PASSWORD_EXPIRED"
	ErrCodePasswordReused     ErrorCode = "PASSWORD_REUSED"

	// 2FA errors
	ErrCode2FARequired ErrorCode = "TWO_FA_REQUIRED"
	ErrCode2FAInvalid  ErrorCode = "TWO_FA_INVALID"
	ErrCode2FAExpired  ErrorCode = "TWO_FA_EXPIRED"

	// Permission errors
	ErrCodeInsufficientPermissions ErrorCode = "INSUFFICIENT_PERMISSIONS"
	ErrCodeRoleNotFound            ErrorCode = "ROLE_NOT_FOUND"

	// Resource errors
	ErrCodeResourceNotFound    ErrorCode = "RESOURCE_NOT_FOUND"
	ErrCodeResourceLocked      ErrorCode = "RESOURCE_LOCKED"
	ErrCodeResourceUnavailable ErrorCode = "RESOURCE_UNAVAILABLE"

	// Validation errors
	ErrCodeValidationFailed   ErrorCode = "VALIDATION_FAILED"
	ErrCodeInvalidFormat      ErrorCode = "INVALID_FORMAT"
	ErrCodeMissingRequired    ErrorCode = "MISSING_REQUIRED"
	ErrCodeValueTooLong       ErrorCode = "VALUE_TOO_LONG"
	ErrCodeValueTooShort      ErrorCode = "VALUE_TOO_SHORT"
	ErrCodeValueOutOfRange    ErrorCode = "VALUE_OUT_OF_RANGE"
)

// Error represents a structured error with code, message, and optional details
type Error struct {
	Code    ErrorCode              // Unique error code
	Message string                 // Human-readable error message
	Details map[string]interface{} // Optional additional details
	Err     error                  // Wrapped underlying error
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error for errors.Is and errors.As
func (e *Error) Unwrap() error {
	return e.Err
}

// WithDetail adds a detail to the error
func (e *Error) WithDetail(key string, value interface{}) *Error {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithDetails adds multiple details to the error
func (e *Error) WithDetails(details map[string]interface{}) *Error {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// HTTPStatusCode returns the appropriate HTTP status code for this error
func (e *Error) HTTPStatusCode() int {
	return MapErrorCodeToHTTPStatus(e.Code)
}

// New creates a new Error with the given code and message
func New(code ErrorCode, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// Newf creates a new Error with formatted message
func Newf(code ErrorCode, format string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// Wrap wraps an existing error with code and message
func Wrap(err error, code ErrorCode, message string) *Error {
	if err == nil {
		return nil
	}
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// Wrapf wraps an existing error with code and formatted message
func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *Error {
	if err == nil {
		return nil
	}
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Err:     err,
	}
}

// IsCode checks if an error has a specific error code
func IsCode(err error, code ErrorCode) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}

// GetCode extracts the error code from an error
// Returns ErrCodeInternal if the error is not a structured Error
func GetCode(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ErrCodeInternal
}

// GetDetails extracts the details from an error
// Returns nil if the error is not a structured Error
func GetDetails(err error) map[string]interface{} {
	var e *Error
	if errors.As(err, &e) {
		return e.Details
	}
	return nil
}

// MapErrorCodeToHTTPStatus maps error codes to HTTP status codes
func MapErrorCodeToHTTPStatus(code ErrorCode) int {
	switch code {
	// 400 Bad Request
	case ErrCodeInvalidInput, ErrCodeValidationFailed, ErrCodeInvalidFormat,
		ErrCodeMissingRequired, ErrCodeValueTooLong, ErrCodeValueTooShort,
		ErrCodeValueOutOfRange, ErrCodePasswordComplexity:
		return http.StatusBadRequest

	// 401 Unauthorized
	case ErrCodeUnauthorized, ErrCodeAuthFailed, ErrCodeInvalidCredentials,
		ErrCodeTokenExpired, ErrCodeTokenInvalid, ErrCodeSessionExpired,
		ErrCode2FARequired, ErrCode2FAInvalid, ErrCode2FAExpired:
		return http.StatusUnauthorized

	// 403 Forbidden
	case ErrCodeForbidden, ErrCodeInsufficientPermissions, ErrCodeUserLocked,
		ErrCodeUserDisabled, ErrCodeEmailNotVerified:
		return http.StatusForbidden

	// 404 Not Found
	case ErrCodeNotFound, ErrCodeUserNotFound, ErrCodeRoleNotFound,
		ErrCodeResourceNotFound:
		return http.StatusNotFound

	// 409 Conflict
	case ErrCodeConflict, ErrCodeAlreadyExists, ErrCodeUserAlreadyExists,
		ErrCodeEmailAlreadyVerified, ErrCodePasswordReused:
		return http.StatusConflict

	// 423 Locked
	case ErrCodeResourceLocked:
		return http.StatusLocked

	// 429 Too Many Requests
	case ErrCodeRateLimitExceeded:
		return http.StatusTooManyRequests

	// 503 Service Unavailable
	case ErrCodeResourceUnavailable, ErrCodeTimeout:
		return http.StatusServiceUnavailable

	// 500 Internal Server Error (default)
	case ErrCodeInternal:
		fallthrough
	default:
		return http.StatusInternalServerError
	}
}

// Common error constructors for frequently used errors

// NotFound creates a "not found" error
func NotFound(resourceType, identifier string) *Error {
	return Newf(ErrCodeNotFound, "%s not found: %s", resourceType, identifier)
}

// AlreadyExists creates an "already exists" error
func AlreadyExists(resourceType, identifier string) *Error {
	return Newf(ErrCodeAlreadyExists, "%s already exists: %s", resourceType, identifier)
}

// InvalidInput creates an "invalid input" error
func InvalidInput(field, reason string) *Error {
	return New(ErrCodeInvalidInput, fmt.Sprintf("invalid %s: %s", field, reason))
}

// Unauthorized creates an "unauthorized" error
func Unauthorized(message string) *Error {
	return New(ErrCodeUnauthorized, message)
}

// Forbidden creates a "forbidden" error
func Forbidden(message string) *Error {
	return New(ErrCodeForbidden, message)
}

// Internal creates an "internal error"
func Internal(message string) *Error {
	return New(ErrCodeInternal, message)
}

// InternalWrap wraps an internal error
func InternalWrap(err error, message string) *Error {
	return Wrap(err, ErrCodeInternal, message)
}

// ValidationFailed creates a "validation failed" error
func ValidationFailed(details map[string]interface{}) *Error {
	return New(ErrCodeValidationFailed, "validation failed").WithDetails(details)
}

// RateLimitExceeded creates a "rate limit exceeded" error
func RateLimitExceeded(retryAfter string) *Error {
	err := New(ErrCodeRateLimitExceeded, "rate limit exceeded")
	if retryAfter != "" {
		err.WithDetail("retry_after", retryAfter)
	}
	return err
}
