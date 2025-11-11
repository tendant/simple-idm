package config

import (
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	if len(e) == 1 {
		return e[0].Error()
	}

	msg := "configuration validation failed:"
	for _, err := range e {
		msg += fmt.Sprintf("\n  - %s", err.Error())
	}
	return msg
}

// HasErrors returns true if there are any validation errors
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// Validator is a function that validates configuration and returns errors
type Validator func() ValidationErrors

// Validate runs multiple validators and combines their errors
func Validate(validators ...Validator) error {
	var allErrors ValidationErrors

	for _, validator := range validators {
		if errs := validator(); len(errs) > 0 {
			allErrors = append(allErrors, errs...)
		}
	}

	if len(allErrors) > 0 {
		return allErrors
	}
	return nil
}

// RequireNonEmpty validates that a string field is not empty
func RequireNonEmpty(field, value string) *ValidationError {
	if value == "" {
		return &ValidationError{
			Field:   field,
			Message: "is required",
		}
	}
	return nil
}

// RequirePositive validates that an integer field is positive
func RequirePositive(field string, value int) *ValidationError {
	if value <= 0 {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be positive, got %d", value),
		}
	}
	return nil
}

// RequireNonNegative validates that an integer field is non-negative
func RequireNonNegative(field string, value int) *ValidationError {
	if value < 0 {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be non-negative, got %d", value),
		}
	}
	return nil
}

// RequirePositiveDuration validates that a duration field is positive
func RequirePositiveDuration(field string, value time.Duration) *ValidationError {
	if value <= 0 {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be positive, got %v", value),
		}
	}
	return nil
}

// RequireNonNegativeDuration validates that a duration field is non-negative
func RequireNonNegativeDuration(field string, value time.Duration) *ValidationError {
	if value < 0 {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be non-negative, got %v", value),
		}
	}
	return nil
}

// RequireInRange validates that an integer is within a range [min, max]
func RequireInRange(field string, value, min, max int) *ValidationError {
	if value < min || value > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be between %d and %d, got %d", min, max, value),
		}
	}
	return nil
}

// RequireValidURL validates that a string is a valid URL
func RequireValidURL(field, value string) *ValidationError {
	if value == "" {
		return &ValidationError{
			Field:   field,
			Message: "is required",
		}
	}

	parsedURL, err := url.Parse(value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("invalid URL: %v", err),
		}
	}

	if parsedURL.Scheme == "" {
		return &ValidationError{
			Field:   field,
			Message: "URL must have a scheme (http:// or https://)",
		}
	}

	return nil
}

// RequireHTTPSURL validates that a string is a valid HTTPS URL
func RequireHTTPSURL(field, value string) *ValidationError {
	if err := RequireValidURL(field, value); err != nil {
		return err
	}

	parsedURL, _ := url.Parse(value)
	if parsedURL.Scheme != "https" {
		return &ValidationError{
			Field:   field,
			Message: "must use HTTPS",
		}
	}

	return nil
}

// RequireValidEmail validates that a string is a valid email address (basic check)
func RequireValidEmail(field, value string) *ValidationError {
	if value == "" {
		return &ValidationError{
			Field:   field,
			Message: "is required",
		}
	}

	// Basic email regex - for more robust validation, use a dedicated library
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(value) {
		return &ValidationError{
			Field:   field,
			Message: "invalid email format",
		}
	}

	return nil
}

// RequireValidPort validates that a port number is valid (1-65535)
func RequireValidPort(field string, value uint16) *ValidationError {
	if value == 0 {
		return &ValidationError{
			Field:   field,
			Message: "port must be between 1 and 65535",
		}
	}
	return nil
}

// RequireOneOf validates that a value is one of the allowed values
func RequireOneOf(field, value string, allowed []string) *ValidationError {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}

	return &ValidationError{
		Field:   field,
		Message: fmt.Sprintf("must be one of %v, got %q", allowed, value),
	}
}

// RequireMinLength validates that a string has a minimum length
func RequireMinLength(field, value string, minLength int) *ValidationError {
	if len(value) < minLength {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at least %d characters, got %d", minLength, len(value)),
		}
	}
	return nil
}

// RequireMaxLength validates that a string does not exceed a maximum length
func RequireMaxLength(field, value string, maxLength int) *ValidationError {
	if len(value) > maxLength {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at most %d characters, got %d", maxLength, len(value)),
		}
	}
	return nil
}

// RequireNonEmptySlice validates that a slice is not empty
func RequireNonEmptySlice(field string, value []string) *ValidationError {
	if len(value) == 0 {
		return &ValidationError{
			Field:   field,
			Message: "must contain at least one value",
		}
	}
	return nil
}

// RequireLessThan validates that a value is less than a threshold
func RequireLessThan(field string, value, threshold int) *ValidationError {
	if value >= threshold {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be less than %d, got %d", threshold, value),
		}
	}
	return nil
}

// RequireGreaterThan validates that a value is greater than a threshold
func RequireGreaterThan(field string, value, threshold int) *ValidationError {
	if value <= threshold {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be greater than %d, got %d", threshold, value),
		}
	}
	return nil
}

// WhenSet returns a validator that only runs if the value is not empty
// Useful for optional configuration fields that should be validated if provided
func WhenSet(value string, validator func() *ValidationError) *ValidationError {
	if value == "" {
		return nil
	}
	return validator()
}

// CollectErrors is a helper to collect validation errors
// Returns nil if no errors, otherwise returns ValidationErrors
func CollectErrors(errors ...*ValidationError) ValidationErrors {
	var result ValidationErrors
	for _, err := range errors {
		if err != nil {
			result = append(result, *err)
		}
	}
	return result
}
