package notice

import (
	"embed"
	"log/slog"

	"github.com/tendant/simple-idm/pkg/notification"
)

// Config holds email service configuration
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

//go:embed templates/*
var templateFiles embed.FS

func loadTemplate(filename string) string {
	content, err := templateFiles.ReadFile(filename)
	if err != nil {
		slog.Error("Error reading template file!", "err", err, "filename", filename)
		return ""
	}
	return string(content)
}

// NewService creates a new email service instance
func NewNotificationManager(smtpConfig notification.SMTPConfig) (*notification.NotificationManager, error) {
	notificationManager := notification.NewNotificationManager()

	emailNotifier, err := notification.NewEmailNotifier(smtpConfig)
	if err != nil {
		return nil, err
	}

	notificationManager.RegisterNotifier(notification.EmailSystem, emailNotifier)

	err = notificationManager.RegisterNotification(notification.UsernameReminderNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Username Reminder",
		Html:    loadTemplate("email/username_reminder.tmpl"),
	})
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(notification.PasswordResetNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Password Reset Request",
		Html:    loadTemplate("email/password_reset.tmpl"),
	})
	if err != nil {
		return nil, err
	}

	// Register notification templates
	err = notificationManager.RegisterNotification(notification.PasswordResetNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Password Reset Request",
		Html:    loadTemplate("email/password_reset.html"),
	})
	if err != nil {
		slog.Error("failed to register password reset notification", "error", err)
		return nil, err
	}

	err = notificationManager.RegisterNotification(notification.UsernameReminderNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Username Reminder",
		Html:    loadTemplate("email/username_reminder.html"),
	})
	if err != nil {
		slog.Error("failed to register username reminder notification", "error", err)
		return nil, err
	}

	return notificationManager, nil
}
