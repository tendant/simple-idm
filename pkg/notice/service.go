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

const (
	UsernameReminder  notification.NoticeType = "username_reminder"
	PasswordResetInit notification.NoticeType = "password_reset_init"
	TwofaCodeNotice   notification.NoticeType = "twofa_code_notice"
)

// NewService creates a new email service instance
func NewNotificationManager(baseUrl string, smtpConfig notification.SMTPConfig) (*notification.NotificationManager, error) {
	notificationManager := notification.NewNotificationManager(baseUrl)

	emailNotifier, err := notification.NewEmailNotifier(smtpConfig)
	if err != nil {
		return nil, err
	}

	notificationManager.RegisterNotifier(notification.EmailSystem, emailNotifier)

	err = notificationManager.RegisterNotification(UsernameReminder, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Username Reminder",
		Html:    loadTemplate("templates/email/username_reminder.html"),
	})
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(PasswordResetInit, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Password Reset Request",
		Html:    loadTemplate("templates/email/password_reset.html"),
	})
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(TwofaCodeNotice, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "2FA Code Init",
		Html:    loadTemplate("templates/email/2fa_code_init.html"),
	})
	if err != nil {
		return nil, err
	}

	return notificationManager, nil
}
