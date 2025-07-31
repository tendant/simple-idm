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
	UsernameReminder       notification.NoticeType = "username_reminder"
	PasswordResetInit      notification.NoticeType = "password_reset_init"
	TwofaCodeNoticeEmail   notification.NoticeType = "twofa_code_notice_email"
	TwofaCodeNoticeSms     notification.NoticeType = "twofa_code_notice_sms"
	MagicLinkLogin         notification.NoticeType = "magic_link_login"
	PasswordResetNotice    notification.NoticeType = "password_reset"
	PasswordUpdateNotice   notification.NoticeType = "password_update"
	UsernameReminderNotice notification.NoticeType = "username_reminder"
)

// NewService creates a new email service instance
func NewNotificationManager(baseUrl string, smtpConfig notification.SMTPConfig, twConfig notification.TwilioConfig) (*notification.NotificationManager, error) {
	notificationManager := notification.NewNotificationManager(baseUrl)

	emailNotifier, err := notification.NewEmailNotifier(smtpConfig)
	if err != nil {
		return nil, err
	}

	smsNotifier := notification.NewSMSNotifier(twConfig)

	notificationManager.RegisterNotifier(notification.EmailSystem, emailNotifier)
	notificationManager.RegisterNotifier(notification.SMSSystem, smsNotifier)

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

	err = notificationManager.RegisterNotification(TwofaCodeNoticeEmail, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "2FA Code Init",
		Html:    loadTemplate("templates/email/2fa_code_notice.html"),
	})
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(MagicLinkLogin, notification.EmailSystem, notification.NoticeTemplate{
		Subject: "Your Login Link",
		Html:    loadTemplate("templates/email/magic_link_login.html"),
	})
	if err != nil {
		return nil, err
	}

	err = notificationManager.RegisterNotification(TwofaCodeNoticeSms, notification.SMSSystem, notification.NoticeTemplate{
		Subject: "2FA Code Init",
		// FIX-ME: SMS does not use HTML, but we keep the structure for consistency
		// Question: how to handle SMS templates?
		Html: loadTemplate(""),
	})
	if err != nil {
		return nil, err
	}

	return notificationManager, nil
}
