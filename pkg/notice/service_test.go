package email

import (
	"os"
	"testing"
)

func TestNewService(t *testing.T) {
	config := Config{
		Host:     "smtp.gmail.com",
		Port:     587,
		Username: "test@example.com",
		Password: "password",
		From:     "test@example.com",
	}

	service, err := NewService(config)
	if err != nil {
		t.Errorf("NewService() error = %v", err)
		return
	}
	if service == nil {
		t.Error("NewService() returned nil service")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Test with required environment variables
	os.Setenv("SMTP_USERNAME", "test@example.com")
	os.Setenv("SMTP_PASSWORD", "password")

	config, err := LoadConfigFromEnv()
	if err != nil {
		t.Errorf("LoadConfigFromEnv() error = %v", err)
		return
	}

	// Check default values
	if config.Host != "smtp.gmail.com" {
		t.Errorf("Expected default host smtp.gmail.com, got %s", config.Host)
	}
	if config.Port != 587 {
		t.Errorf("Expected default port 587, got %d", config.Port)
	}
	if config.From != "test@example.com" {
		t.Errorf("Expected from to match username, got %s", config.From)
	}

	// Test with custom values
	os.Setenv("SMTP_HOST", "custom.smtp.com")
	os.Setenv("SMTP_PORT", "465")
	os.Setenv("SMTP_FROM", "custom@example.com")

	config, err = LoadConfigFromEnv()
	if err != nil {
		t.Errorf("LoadConfigFromEnv() error = %v", err)
		return
	}

	if config.Host != "custom.smtp.com" {
		t.Errorf("Expected custom host custom.smtp.com, got %s", config.Host)
	}
	if config.Port != 465 {
		t.Errorf("Expected custom port 465, got %d", config.Port)
	}
	if config.From != "custom@example.com" {
		t.Errorf("Expected custom from custom@example.com, got %s", config.From)
	}
}

func TestService_SendEmail(t *testing.T) {
	// Skip if not in integration test mode
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	config, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	err = service.SendEmail("test@example.com", "Test Subject", "Test Body")
	if err != nil {
		t.Errorf("SendEmail() error = %v", err)
	}
}
