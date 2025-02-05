package notice

import (
	"fmt"
	"os"
	"strconv"
)

// LoadConfigFromEnv loads email configuration from environment variables
func LoadConfigFromEnv() (Config, error) {
	port, err := strconv.Atoi(getEnvOrDefault("SMTP_PORT", "587"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	config := Config{
		Host:     getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     getEnvOrDefault("SMTP_FROM", os.Getenv("SMTP_USERNAME")),
	}

	// Validate required fields
	if config.Username == "" {
		return Config{}, fmt.Errorf("SMTP_USERNAME is required")
	}
	if config.Password == "" {
		return Config{}, fmt.Errorf("SMTP_PASSWORD is required")
	}

	return config, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
