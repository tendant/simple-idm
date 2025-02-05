package notice

import (
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

// NewService creates a new email service instance
func NewNotificationManager(smtpConfig notification.SMTPConfig) (*notification.NotificationManager, error) {
	notificationManager := notification.NewNotificationManager()

	emailNotifier, err := notification.NewEmailNotifier(smtpConfig)
	if err != nil {
		return nil, err
	}

	notificationManager.RegisterNotifier(notification.EmailSystem, emailNotifier)

	err = notificationManager.RegisterNotification(notification.NoticeType("username_reminder"), notification.EmailSystem, notification.NoticeTemplate{Subject: "Username Reminder", BodyPath: "templates/username_reminder.tmpl"})
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(notification.NoticeType("password_reminder"), notification.EmailSystem, notification.NoticeTemplate{Subject: "Password Reminder", BodyPath: "templates/password_reminder.tmpl"})
	if err != nil {
		return nil, err
	}

	// Register notification templates
	err = notificationManager.RegisterNotification(notification.PasswordResetNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject:  "Password Reset Request",
		BodyPath: "templates/email/password_reset.html",
	})
	if err != nil {
		slog.Error("failed to register password reset notification", "error", err)
		return nil, err
	}

	err = notificationManager.RegisterNotification(notification.UsernameReminderNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject:  "Username Reminder",
		BodyPath: "templates/email/username_reminder.html",
	})
	if err != nil {
		slog.Error("failed to register username reminder notification", "error", err)
		return nil, err
	}

	return notificationManager, nil
}
