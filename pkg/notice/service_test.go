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
	}

	manager, err := NewNotificationManager(smtpConfig)
	if err != nil {
		t.Errorf("NewNotificationManager() error = %v", err)
		return
	}
	if manager == nil {
		t.Error("NewService() returned nil service")
	}

	// Test that notifications are properly registered
	nm := manager
	if nm == nil {
		t.Error("NotificationManager is nil")
		return
	}

	// Test sending a username reminder
	err = nm.Send(notification.NoticeType("username_reminder"), notification.NotificationData{
		To:      "test@example.com",
		Subject: "Username Reminder",
		Body:    "Your username is: testuser",
	})
	if err != nil {
		t.Errorf("Failed to send username reminder: %v", err)
	}

	// Test sending a password reminder
	err = nm.Send(notification.NoticeType("password_reminder"), notification.NotificationData{
		To:      "test@example.com",
		Subject: "Password Reminder",
		Body:    "Your password reset link is: https://example.com/reset",
	})
	if err != nil {
		t.Errorf("Failed to send password reminder: %v", err)
	}
}
