package email

import (
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

// Service provides email sending functionality
type NoticeService struct {
	notificationManager *notification.NotificationManager
}

// NewService creates a new email service instance
func NewService(smtpConfig notification.SMTPConfig) (*NoticeService, error) {
	notificationManager := notification.NewNotificationManager()

	emailNotifier, err := notification.NewEmailNotifier(smtpConfig)
	if err != nil {
		return nil, err
	}

	notificationManager.RegisterNotifier(notification.EmailSystem, emailNotifier)

	err = notificationManager.RegisterNotification(notification.NotificationType("username_reminder"), notification.EmailSystem, "Username Reminder", "templates/username_reminder.tmpl")
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(notification.NotificationType("password_reminder"), notification.EmailSystem, "Password Reminder", "templates/password_reminder.tmpl")
	if err != nil {
		return nil, err
	}

	return &NoticeService{
		notificationManager: notificationManager,
	}, nil
}
