package config

import (
	"log/slog"

	"github.com/sosodev/duration"
	"github.com/tendant/simple-idm/pkg/login"
)

// PasswordComplexityConfig holds password policy configuration from environment variables
// This is shared across all services to avoid duplication
type PasswordComplexityConfig struct {
	Enabled                 bool   `env:"PASSWORD_POLICY_ENABLED" env-default:"true"`
	RequiredDigit           bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_DIGIT" env-default:"true"`
	RequiredLowercase       bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_LOWERCASE" env-default:"true"`
	RequiredNonAlphanumeric bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_NON_ALPHANUMERIC" env-default:"true"`
	RequiredUppercase       bool   `env:"PASSWORD_COMPLEXITY_REQUIRE_UPPERCASE" env-default:"true"`
	RequiredLength          int    `env:"PASSWORD_COMPLEXITY_REQUIRED_LENGTH" env-default:"8"`
	DisallowCommonPwds      bool   `env:"PASSWORD_COMPLEXITY_DISALLOW_COMMON_PWDS" env-default:"true"`
	MaxRepeatedChars        int    `env:"PASSWORD_COMPLEXITY_MAX_REPEATED_CHARS" env-default:"3"`
	HistoryCheckCount       int    `env:"PASSWORD_COMPLEXITY_HISTORY_CHECK_COUNT" env-default:"0"`
	ExpirationPeriod        string `env:"PASSWORD_COMPLEXITY_EXPIRATION_PERIOD" env-default:"P100Y"`      // 100 years
	MinPasswordAgePeriod    string `env:"PASSWORD_COMPLEXITY_MIN_PASSWORD_AGE_PERIOD" env-default:"PT0M"` // 0 minutes
}

// ToPasswordPolicy converts the configuration to a login.PasswordPolicy
// This centralizes the conversion logic that was duplicated across all services
func (c *PasswordComplexityConfig) ToPasswordPolicy() *login.PasswordPolicy {
	// If no config is provided, use the default policy
	if c == nil {
		return login.DefaultPasswordPolicy()
	}

	// If policy is disabled, return no-op policy
	if !c.Enabled {
		return login.NoOpPasswordPolicy()
	}

	// Parse duration strings
	expirationPeriod, err := duration.Parse(c.ExpirationPeriod)
	if err != nil {
		slog.Error("Failed to parse expiration period", "err", err)
		expirationPeriod = &duration.Duration{} // fallback to zero
	}

	minPasswordAgePeriod, err := duration.Parse(c.MinPasswordAgePeriod)
	if err != nil {
		slog.Error("Failed to parse min password age period", "err", err)
		minPasswordAgePeriod = &duration.Duration{} // fallback to zero
	}

	slog.Info("Password policy configuration",
		"enabled", c.Enabled,
		"minLength", c.RequiredLength,
		"expirationPeriod", expirationPeriod.ToTimeDuration(),
		"minPasswordAge", minPasswordAgePeriod.ToTimeDuration(),
		"historyCheck", c.HistoryCheckCount,
	)

	// Create a policy based on the configuration
	return &login.PasswordPolicy{
		MinLength:            c.RequiredLength,
		RequireUppercase:     c.RequiredUppercase,
		RequireLowercase:     c.RequiredLowercase,
		RequireDigit:         c.RequiredDigit,
		RequireSpecialChar:   c.RequiredNonAlphanumeric,
		DisallowCommonPwds:   c.DisallowCommonPwds,
		MaxRepeatedChars:     c.MaxRepeatedChars,
		HistoryCheckCount:    c.HistoryCheckCount,
		ExpirationPeriod:     expirationPeriod.ToTimeDuration(),
		CommonPasswordsPath:  "",
		MinPasswordAgePeriod: minPasswordAgePeriod.ToTimeDuration(),
	}
}

// MustToPasswordPolicy is like ToPasswordPolicy but panics on error
// Use this during service initialization when failure should be fatal
func (c *PasswordComplexityConfig) MustToPasswordPolicy() *login.PasswordPolicy {
	policy := c.ToPasswordPolicy()
	if policy == nil {
		panic("failed to create password policy from config")
	}
	return policy
}

// ProductionDefaults returns production-ready password policy configuration
func ProductionDefaults() *PasswordComplexityConfig {
	return &PasswordComplexityConfig{
		Enabled:                 true,
		RequiredDigit:           true,
		RequiredLowercase:       true,
		RequiredNonAlphanumeric: true,
		RequiredUppercase:       true,
		RequiredLength:          8,
		DisallowCommonPwds:      true,
		MaxRepeatedChars:        3,
		HistoryCheckCount:       0,
		ExpirationPeriod:        "P100Y", // 100 years (effectively disabled)
		MinPasswordAgePeriod:    "PT0M",  // 0 minutes (disabled)
	}
}

// DevelopmentDefaults returns relaxed password policy configuration for development
func DevelopmentDefaults() *PasswordComplexityConfig {
	return &PasswordComplexityConfig{
		Enabled:                 false, // No validation in development
		RequiredDigit:           false,
		RequiredLowercase:       false,
		RequiredNonAlphanumeric: false,
		RequiredUppercase:       false,
		RequiredLength:          1,
		DisallowCommonPwds:      false,
		MaxRepeatedChars:        0,
		HistoryCheckCount:       0,
		ExpirationPeriod:        "P100Y",
		MinPasswordAgePeriod:    "PT0M",
	}
}

// EnterpriseDefaults returns strict password policy configuration for compliance
func EnterpriseDefaults() *PasswordComplexityConfig {
	return &PasswordComplexityConfig{
		Enabled:                 true,
		RequiredDigit:           true,
		RequiredLowercase:       true,
		RequiredNonAlphanumeric: true,
		RequiredUppercase:       true,
		RequiredLength:          12,
		DisallowCommonPwds:      true,
		MaxRepeatedChars:        2,
		HistoryCheckCount:       5,
		ExpirationPeriod:        "P90D", // 90 days
		MinPasswordAgePeriod:    "P1D",  // 1 day
	}
}
