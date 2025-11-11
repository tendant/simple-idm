// Package errors provides structured error handling with error codes for simple-idm.
//
// This package standardizes error handling across all services with typed error codes,
// structured error details, and automatic HTTP status code mapping.
//
// # Overview
//
// The errors package provides:
//   - Structured Error type with error codes
//   - 40+ predefined error codes for common scenarios
//   - Error wrapping with context
//   - HTTP status code mapping
//   - Error inspection utilities
//
// # Basic Usage
//
// Creating errors with codes:
//
//	import "github.com/tendant/simple-idm/pkg/errors"
//
//	// Create a simple error
//	err := errors.New(errors.ErrCodeUserNotFound, "user not found")
//
//	// Create error with formatted message
//	err := errors.Newf(errors.ErrCodeInvalidInput, "invalid email: %s", email)
//
//	// Wrap an existing error
//	err := errors.Wrap(dbErr, errors.ErrCodeInternal, "failed to query database")
//
//	// Use convenience constructors
//	err := errors.NotFound("user", userID)
//	err := errors.AlreadyExists("username", username)
//	err := errors.InvalidInput("email", "invalid format")
//
// # Error Codes
//
// All error codes are strongly typed and organized by category:
//
// Generic:
//   - ErrCodeInternal
//   - ErrCodeInvalidInput
//   - ErrCodeNotFound
//   - ErrCodeAlreadyExists
//   - ErrCodeUnauthorized
//   - ErrCodeForbidden
//   - ErrCodeConflict
//
// Authentication:
//   - ErrCodeAuthFailed
//   - ErrCodeInvalidCredentials
//   - ErrCodeTokenExpired
//   - ErrCodeTokenInvalid
//   - ErrCodeSessionExpired
//
// User/Account:
//   - ErrCodeUserNotFound
//   - ErrCodeUserAlreadyExists
//   - ErrCodeUserLocked
//   - ErrCodeUserDisabled
//   - ErrCodeEmailNotVerified
//
// See errors.go for the complete list of error codes.
//
// # Error Details
//
// Add structured details to errors for better debugging:
//
//	err := errors.NotFound("user", userID).
//		WithDetail("user_id", userID).
//		WithDetail("search_by", "email")
//
//	// Add multiple details at once
//	err := errors.ValidationFailed(map[string]interface{}{
//		"field": "password",
//		"min_length": 8,
//		"actual_length": 5,
//	})
//
// # Error Wrapping
//
// Wrap lower-level errors to add context:
//
//	user, err := repo.GetUser(id)
//	if err != nil {
//		return errors.Wrap(err, errors.ErrCodeUserNotFound,
//			"failed to get user from database")
//	}
//
//	// With formatted message
//	if err != nil {
//		return errors.Wrapf(err, errors.ErrCodeInternal,
//			"failed to load user %s", userID)
//	}
//
// # Error Inspection
//
// Check error codes and extract information:
//
//	// Check if error has specific code
//	if errors.IsCode(err, errors.ErrCodeUserNotFound) {
//		// Handle not found case
//	}
//
//	// Get error code
//	code := errors.GetCode(err)
//
//	// Get error details
//	details := errors.GetDetails(err)
//	if userID, ok := details["user_id"].(string); ok {
//		log.Printf("Failed for user: %s", userID)
//	}
//
//	// Standard error wrapping still works
//	if errors.Is(err, sql.ErrNoRows) {
//		// Handle no rows
//	}
//
// # HTTP Status Code Mapping
//
// Automatically map errors to HTTP status codes:
//
//	func handleError(w http.ResponseWriter, err error) {
//		var structuredErr *errors.Error
//		if errors.As(err, &structuredErr) {
//			statusCode := structuredErr.HTTPStatusCode()
//			http.Error(w, structuredErr.Message, statusCode)
//			return
//		}
//		http.Error(w, "Internal server error", 500)
//	}
//
// Error code to HTTP status mapping:
//   - ErrCodeInvalidInput → 400 Bad Request
//   - ErrCodeUnauthorized → 401 Unauthorized
//   - ErrCodeForbidden → 403 Forbidden
//   - ErrCodeNotFound → 404 Not Found
//   - ErrCodeConflict → 409 Conflict
//   - ErrCodeRateLimitExceeded → 429 Too Many Requests
//   - ErrCodeInternal → 500 Internal Server Error
//
// # Service Layer Example
//
// Using structured errors in a service:
//
//	type UserService struct {
//		repo UserRepository
//	}
//
//	func (s *UserService) GetUser(ctx context.Context, id string) (*User, error) {
//		user, err := s.repo.FindByID(ctx, id)
//		if err != nil {
//			if err == sql.ErrNoRows {
//				return nil, errors.NotFound("user", id)
//			}
//			return nil, errors.InternalWrap(err, "failed to query user")
//		}
//
//		if user.Deleted {
//			return nil, errors.NotFound("user", id)
//		}
//
//		if user.Locked {
//			return nil, errors.New(errors.ErrCodeUserLocked, "user account is locked").
//				WithDetail("locked_until", user.LockedUntil)
//		}
//
//		return user, nil
//	}
//
//	func (s *UserService) CreateUser(ctx context.Context, email string) (*User, error) {
//		// Validate input
//		if !isValidEmail(email) {
//			return nil, errors.InvalidInput("email", "invalid format")
//		}
//
//		// Check if exists
//		exists, err := s.repo.ExistsByEmail(ctx, email)
//		if err != nil {
//			return nil, errors.InternalWrap(err, "failed to check user existence")
//		}
//		if exists {
//			return nil, errors.AlreadyExists("user", email)
//		}
//
//		// Create user
//		user, err := s.repo.Create(ctx, email)
//		if err != nil {
//			return nil, errors.InternalWrap(err, "failed to create user")
//		}
//
//		return user, nil
//	}
//
// # HTTP Handler Example
//
// Using structured errors in HTTP handlers:
//
//	func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
//		userID := chi.URLParam(r, "id")
//
//		user, err := h.service.GetUser(r.Context(), userID)
//		if err != nil {
//			h.handleError(w, err)
//			return
//		}
//
//		respondJSON(w, http.StatusOK, user)
//	}
//
//	func (h *UserHandler) handleError(w http.ResponseWriter, err error) {
//		var structuredErr *errors.Error
//		if !errors.As(err, &structuredErr) {
//			// Not a structured error, log and return generic error
//			log.Printf("Unstructured error: %v", err)
//			respondJSON(w, http.StatusInternalServerError, map[string]string{
//				"error": "Internal server error",
//			})
//			return
//		}
//
//		// Build error response
//		response := map[string]interface{}{
//			"error": structuredErr.Message,
//			"code":  structuredErr.Code,
//		}
//
//		// Include details if present (but filter sensitive info)
//		if structuredErr.Details != nil {
//			response["details"] = filterSensitiveDetails(structuredErr.Details)
//		}
//
//		statusCode := structuredErr.HTTPStatusCode()
//		respondJSON(w, statusCode, response)
//	}
//
// # Validation Example
//
// Using errors for validation:
//
//	func (s *UserService) ValidateUser(user *User) error {
//		validationErrors := make(map[string]interface{})
//
//		if user.Email == "" {
//			validationErrors["email"] = "required"
//		} else if !isValidEmail(user.Email) {
//			validationErrors["email"] = "invalid format"
//		}
//
//		if len(user.Password) < 8 {
//			validationErrors["password"] = map[string]interface{}{
//				"error": "too short",
//				"min_length": 8,
//				"actual_length": len(user.Password),
//			}
//		}
//
//		if len(validationErrors) > 0 {
//			return errors.ValidationFailed(validationErrors)
//		}
//
//		return nil
//	}
//
// # Error Logging
//
// Log errors with full context:
//
//	if err != nil {
//		code := errors.GetCode(err)
//		details := errors.GetDetails(err)
//
//		log.Printf("Operation failed: code=%s, error=%v, details=%v",
//			code, err, details)
//
//		return err
//	}
//
// # Migration from Simple Errors
//
// Before (simple errors):
//
//	var ErrUserNotFound = errors.New("user not found")
//
//	func GetUser(id string) (*User, error) {
//		// ...
//		if notFound {
//			return nil, ErrUserNotFound
//		}
//	}
//
// After (structured errors):
//
//	func GetUser(id string) (*User, error) {
//		// ...
//		if notFound {
//			return nil, errors.NotFound("user", id)
//		}
//	}
//
// Before (error wrapping):
//
//	if err != nil {
//		return fmt.Errorf("failed to get user: %w", err)
//	}
//
// After (structured wrapping):
//
//	if err != nil {
//		return errors.Wrap(err, errors.ErrCodeInternal,
//			"failed to get user")
//	}
//
// # Best Practices
//
// 1. Use specific error codes
//   - Choose the most specific code that describes the error
//   - Don't overuse ErrCodeInternal - use specific codes
//
// 2. Add helpful details
//   - Include identifiers (user ID, resource ID)
//   - Add context that helps debugging
//   - Don't include sensitive data (passwords, tokens)
//
// 3. Wrap errors at boundaries
//   - Wrap database errors at repository layer
//   - Wrap external service errors at integration layer
//   - Keep business logic errors unwrapped
//
// 4. Handle errors at the right level
//   - Service layer: Create structured errors
//   - HTTP layer: Convert to HTTP responses
//   - Don't log the same error multiple times
//
// 5. Use convenience constructors
//   - NotFound() for not found errors
//   - AlreadyExists() for conflicts
//   - InvalidInput() for validation errors
//
// # Common Patterns
//
// Pattern 1: Database error handling
//
//	user, err := repo.GetByID(ctx, id)
//	if err != nil {
//		if errors.Is(err, sql.ErrNoRows) {
//			return nil, errors.NotFound("user", id)
//		}
//		return nil, errors.InternalWrap(err, "database query failed")
//	}
//
// Pattern 2: Validation with multiple fields
//
//	validationErrs := make(map[string]interface{})
//	if email == "" {
//		validationErrs["email"] = "required"
//	}
//	if password == "" {
//		validationErrs["password"] = "required"
//	}
//	if len(validationErrs) > 0 {
//		return errors.ValidationFailed(validationErrs)
//	}
//
// Pattern 3: Conditional error codes
//
//	if user.Locked {
//		return errors.New(errors.ErrCodeUserLocked, "account locked")
//	}
//	if user.Disabled {
//		return errors.New(errors.ErrCodeUserDisabled, "account disabled")
//	}
//	if !user.EmailVerified && requiresVerification {
//		return errors.New(errors.ErrCodeEmailNotVerified, "email not verified")
//	}
//
// # Testing
//
// Test error handling:
//
//	func TestGetUser_NotFound(t *testing.T) {
//		service := setupTest(t)
//
//		_, err := service.GetUser(ctx, "unknown-id")
//
//		assert.Error(t, err)
//		assert.True(t, errors.IsCode(err, errors.ErrCodeUserNotFound))
//
//		var structuredErr *errors.Error
//		if assert.True(t, errors.As(err, &structuredErr)) {
//			assert.Equal(t, errors.ErrCodeUserNotFound, structuredErr.Code)
//			assert.Equal(t, http.StatusNotFound, structuredErr.HTTPStatusCode())
//		}
//	}
package errors
