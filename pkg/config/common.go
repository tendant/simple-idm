package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// GetEnv retrieves an environment variable value
// Returns empty string if not set
func GetEnv(key string) string {
	return os.Getenv(key)
}

// GetEnvOrDefault retrieves an environment variable or returns a default value
// This is a common pattern used across all configuration loading
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// MustGetEnv retrieves an environment variable or panics if not set
// Use this for required configuration during service initialization
func MustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return value
}

// GetEnvInt retrieves an environment variable as an integer
// Returns the default value if not set or invalid
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// MustGetEnvInt retrieves an environment variable as an integer or panics
// Use this for required integer configuration during service initialization
func MustGetEnvInt(key string) int {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	intVal, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("environment variable %s is not a valid integer: %v", key, err))
	}
	return intVal
}

// GetEnvUint16 retrieves an environment variable as a uint16 (useful for ports)
// Returns the default value if not set or invalid
func GetEnvUint16(key string, defaultValue uint16) uint16 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseUint(value, 10, 16); err == nil {
			return uint16(intVal)
		}
	}
	return defaultValue
}

// GetEnvBool retrieves an environment variable as a boolean
// Accepts: "true", "1", "yes", "on" (case-insensitive) for true
// Returns the default value if not set or invalid
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		switch value {
		case "true", "1", "yes", "on", "True", "TRUE", "Yes", "YES", "On", "ON":
			return true
		case "false", "0", "no", "off", "False", "FALSE", "No", "NO", "Off", "OFF":
			return false
		}
	}
	return defaultValue
}

// GetEnvDuration retrieves an environment variable as a time.Duration
// Supports Go duration strings (e.g., "5m", "1h30m", "24h")
// Returns the default value if not set or invalid
func GetEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// MustGetEnvDuration retrieves an environment variable as a time.Duration or panics
// Use this for required duration configuration during service initialization
func MustGetEnvDuration(key string) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		panic(fmt.Sprintf("environment variable %s is not a valid duration: %v", key, err))
	}
	return duration
}

// ParseDurationValue parses either a string or time.Duration into time.Duration
// This is useful when accepting configuration from multiple sources
// (environment variables as strings, programmatic configuration as time.Duration)
func ParseDurationValue(v interface{}) (time.Duration, error) {
	switch val := v.(type) {
	case time.Duration:
		return val, nil
	case string:
		if val == "" {
			return 0, nil
		}
		return time.ParseDuration(val)
	default:
		return 0, fmt.Errorf("invalid duration type: %T", v)
	}
}

// GetEnvSlice retrieves a comma-separated environment variable as a slice of strings
// Empty values are filtered out, and each value is trimmed
func GetEnvSlice(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	parts := splitAndTrim(value, ",")
	if len(parts) == 0 {
		return defaultValue
	}
	return parts
}

// splitAndTrim splits a string by separator and trims each part
// Empty parts are filtered out
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}

	parts := []string{}
	for _, part := range splitString(s, sep) {
		if trimmed := trimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// Helper functions to avoid importing strings package
func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}

	result := []string{}
	start := 0

	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}

	return s[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// Environment represents different deployment environments
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
	Test        Environment = "test"
)

// GetEnvironment returns the current environment from APP_ENV or defaults to development
func GetEnvironment() Environment {
	env := GetEnvOrDefault("APP_ENV", "development")
	switch env {
	case "production", "prod":
		return Production
	case "staging", "stage":
		return Staging
	case "test", "testing":
		return Test
	default:
		return Development
	}
}

// IsDevelopment returns true if running in development environment
func IsDevelopment() bool {
	return GetEnvironment() == Development
}

// IsProduction returns true if running in production environment
func IsProduction() bool {
	return GetEnvironment() == Production
}

// IsStaging returns true if running in staging environment
func IsStaging() bool {
	return GetEnvironment() == Staging
}

// IsTest returns true if running in test environment
func IsTest() bool {
	return GetEnvironment() == Test
}
