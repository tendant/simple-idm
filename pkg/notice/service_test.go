package notice

import (
	"testing"

	"github.com/tendant/simple-idm/pkg/notification"
)

func TestNewService(t *testing.T) {
	smtpConfig := notification.SMTPConfig{
		Host:     "smtp.gmail.com",
		Port:     587,
		Username: "test@example.com",
		Password: "password",
		From:     "noreply@example.com", // Add required From address
	}

	manager, err := NewNotificationManager(
		"http://localhost:3000",
		WithSMTP(smtpConfig),
		WithDefaultTemplates(),
	)
	if err != nil {
		t.Errorf("NewNotificationManager() error = %v", err)
		return
	}
	if manager == nil {
		t.Error("NewService() returned nil service")
		return
	}

	// Test that the notification manager was created successfully
	// Note: We don't actually send emails in the test as that would require a real SMTP server
	// In a production environment, you would use a mock SMTP server or integration tests

	t.Log("NotificationManager created successfully with SMTP and default templates")
}
