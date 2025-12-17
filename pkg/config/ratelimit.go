package config

// RateLimitConfig contains rate limiting settings.
// Fields have no env tags - populate manually or use NewRateLimitConfigFromEnv() for standard env var names.
type RateLimitConfig struct {
	// Global rate limiting
	GlobalEnabled    bool
	GlobalCapacity   int
	GlobalRefillRate float64 // tokens per second

	// Per-IP rate limiting
	PerIPEnabled    bool
	PerIPCapacity   int
	PerIPRefillRate float64 // tokens per second

	// Per-User rate limiting (for authenticated requests)
	PerUserEnabled    bool
	PerUserCapacity   int
	PerUserRefillRate float64 // tokens per second

	// Login endpoint specific limits (to prevent brute force)
	LoginEnabled    bool
	LoginCapacity   int
	LoginRefillRate float64 // tokens per second

	// Signup endpoint specific limits
	SignupEnabled    bool
	SignupCapacity   int
	SignupRefillRate float64 // tokens per second

	// Password reset endpoint specific limits
	PasswordResetEnabled    bool
	PasswordResetCapacity   int
	PasswordResetRefillRate float64 // tokens per second

	// IncludeHeaders controls whether rate limit headers are included in responses
	IncludeHeaders bool
}

// DefaultRateLimitConfig returns a RateLimitConfig with sensible defaults
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		// Global: ~1000 requests per minute
		GlobalEnabled:    true,
		GlobalCapacity:   1000,
		GlobalRefillRate: 16.67,

		// Per-IP: ~100 requests per minute
		PerIPEnabled:    true,
		PerIPCapacity:   100,
		PerIPRefillRate: 1.67,

		// Per-User: ~200 requests per minute
		PerUserEnabled:    true,
		PerUserCapacity:   200,
		PerUserRefillRate: 3.33,

		// Login: 10 per minute (brute force protection)
		LoginEnabled:    true,
		LoginCapacity:   10,
		LoginRefillRate: 0.167,

		// Signup: 5 per 5 minutes
		SignupEnabled:    true,
		SignupCapacity:   5,
		SignupRefillRate: 0.017,

		// Password reset: 3 per hour
		PasswordResetEnabled:    true,
		PasswordResetCapacity:   3,
		PasswordResetRefillRate: 0.00083,

		IncludeHeaders: true,
	}
}

// NewRateLimitConfigFromEnv loads RateLimitConfig from standard environment variables.
// This is an optional convenience function - you can also populate the struct manually.
//
// Environment variables:
//   - RATELIMIT_GLOBAL_ENABLED: Enable global rate limiting (default: true)
//   - RATELIMIT_GLOBAL_CAPACITY: Global bucket capacity (default: 1000)
//   - RATELIMIT_GLOBAL_REFILL_RATE: Global refill rate in tokens/sec (default: 16.67)
//   - RATELIMIT_PER_IP_ENABLED: Enable per-IP rate limiting (default: true)
//   - RATELIMIT_PER_IP_CAPACITY: Per-IP bucket capacity (default: 100)
//   - RATELIMIT_PER_IP_REFILL_RATE: Per-IP refill rate in tokens/sec (default: 1.67)
//   - RATELIMIT_PER_USER_ENABLED: Enable per-user rate limiting (default: true)
//   - RATELIMIT_PER_USER_CAPACITY: Per-user bucket capacity (default: 200)
//   - RATELIMIT_PER_USER_REFILL_RATE: Per-user refill rate in tokens/sec (default: 3.33)
//   - RATELIMIT_LOGIN_ENABLED: Enable login endpoint rate limiting (default: true)
//   - RATELIMIT_LOGIN_CAPACITY: Login bucket capacity (default: 10)
//   - RATELIMIT_LOGIN_REFILL_RATE: Login refill rate in tokens/sec (default: 0.167)
//   - RATELIMIT_SIGNUP_ENABLED: Enable signup endpoint rate limiting (default: true)
//   - RATELIMIT_SIGNUP_CAPACITY: Signup bucket capacity (default: 5)
//   - RATELIMIT_SIGNUP_REFILL_RATE: Signup refill rate in tokens/sec (default: 0.017)
//   - RATELIMIT_PASSWORD_RESET_ENABLED: Enable password reset endpoint rate limiting (default: true)
//   - RATELIMIT_PASSWORD_RESET_CAPACITY: Password reset bucket capacity (default: 3)
//   - RATELIMIT_PASSWORD_RESET_REFILL_RATE: Password reset refill rate in tokens/sec (default: 0.00083)
//   - RATELIMIT_INCLUDE_HEADERS: Include rate limit headers in responses (default: true)
func NewRateLimitConfigFromEnv() RateLimitConfig {
	return RateLimitConfig{
		GlobalEnabled:           GetEnvBool("RATELIMIT_GLOBAL_ENABLED", true),
		GlobalCapacity:          GetEnvInt("RATELIMIT_GLOBAL_CAPACITY", 1000),
		GlobalRefillRate:        GetEnvFloat64("RATELIMIT_GLOBAL_REFILL_RATE", 16.67),
		PerIPEnabled:            GetEnvBool("RATELIMIT_PER_IP_ENABLED", true),
		PerIPCapacity:           GetEnvInt("RATELIMIT_PER_IP_CAPACITY", 100),
		PerIPRefillRate:         GetEnvFloat64("RATELIMIT_PER_IP_REFILL_RATE", 1.67),
		PerUserEnabled:          GetEnvBool("RATELIMIT_PER_USER_ENABLED", true),
		PerUserCapacity:         GetEnvInt("RATELIMIT_PER_USER_CAPACITY", 200),
		PerUserRefillRate:       GetEnvFloat64("RATELIMIT_PER_USER_REFILL_RATE", 3.33),
		LoginEnabled:            GetEnvBool("RATELIMIT_LOGIN_ENABLED", true),
		LoginCapacity:           GetEnvInt("RATELIMIT_LOGIN_CAPACITY", 10),
		LoginRefillRate:         GetEnvFloat64("RATELIMIT_LOGIN_REFILL_RATE", 0.167),
		SignupEnabled:           GetEnvBool("RATELIMIT_SIGNUP_ENABLED", true),
		SignupCapacity:          GetEnvInt("RATELIMIT_SIGNUP_CAPACITY", 5),
		SignupRefillRate:        GetEnvFloat64("RATELIMIT_SIGNUP_REFILL_RATE", 0.017),
		PasswordResetEnabled:    GetEnvBool("RATELIMIT_PASSWORD_RESET_ENABLED", true),
		PasswordResetCapacity:   GetEnvInt("RATELIMIT_PASSWORD_RESET_CAPACITY", 3),
		PasswordResetRefillRate: GetEnvFloat64("RATELIMIT_PASSWORD_RESET_REFILL_RATE", 0.00083),
		IncludeHeaders:          GetEnvBool("RATELIMIT_INCLUDE_HEADERS", true),
	}
}
