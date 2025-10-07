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
	UsernameReminder        notification.NoticeType = "username_reminder"
	PasswordResetInit       notification.NoticeType = "password_reset_init"
	TwofaCodeNoticeEmail    notification.NoticeType = "twofa_code_notice_email"
	TwofaCodeNoticeSms      notification.NoticeType = "twofa_code_notice_sms"
	MagicLinkLogin          notification.NoticeType = "magic_link_login"
	PasswordResetNotice     notification.NoticeType = "password_reset"
	PasswordUpdateNotice    notification.NoticeType = "password_update"
	UsernameReminderNotice  notification.NoticeType = "username_reminder"
	PhoneVerificationNotice notification.NoticeType = "phone_verification"
	EmailVerification       notification.NoticeType = "email_verification"
)

// NotificationManagerOption is a function that configures a NotificationManager
type NotificationManagerOption func(*notification.NotificationManager) error

// WithSMTP adds an email notifier with the provided SMTP configuration
func WithSMTP(config notification.SMTPConfig) NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		emailNotifier, err := notification.NewEmailNotifier(config)
		if err != nil {
			return err
		}
		nm.RegisterNotifier(notification.EmailSystem, emailNotifier)
		return nil
	}
}

// WithTwilio adds an SMS notifier with the provided Twilio configuration
func WithTwilio(config notification.TwilioConfig) NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		smsNotifier := notification.NewSMSNotifier(config)
		nm.RegisterNotifier(notification.SMSSystem, smsNotifier)
		return nil
	}
}

// WithUsernameReminderTemplate registers the username reminder template
func WithUsernameReminderTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(UsernameReminder, notification.EmailSystem, notification.NoticeTemplate{
			Subject: "Username Reminder",
			Html:    loadTemplate("templates/email/username_reminder.html"),
		})
	}
}

// WithPasswordResetTemplate registers the password reset template
func WithPasswordResetTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(PasswordResetInit, notification.EmailSystem, notification.NoticeTemplate{
			Subject: "Password Reset Request",
			Html:    loadTemplate("templates/email/password_reset.html"),
		})
	}
}

// WithTwofaCodeEmailTemplate registers the 2FA code email template
func WithTwofaCodeEmailTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(TwofaCodeNoticeEmail, notification.EmailSystem, notification.NoticeTemplate{
			Subject: "2FA Code Init",
			Html:    loadTemplate("templates/email/2fa_code_notice.html"),
		})
	}
}

// WithMagicLinkLoginTemplate registers the magic link login template
func WithMagicLinkLoginTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(MagicLinkLogin, notification.EmailSystem, notification.NoticeTemplate{
			Subject: "Your Login Link",
			Html:    loadTemplate("templates/email/magic_link_login.html"),
		})
	}
}

// WithTwofaCodeSmsTemplate registers the 2FA code SMS template
func WithTwofaCodeSmsTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(TwofaCodeNoticeSms, notification.SMSSystem, notification.NoticeTemplate{
			Subject: "2FA Code Init",
			Text:    "Your 2FA code is: {{.TwofaPasscode}}",
		})
	}
}

func WithPhoneVerificationTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(PhoneVerificationNotice, notification.SMSSystem, notification.NoticeTemplate{
			Subject: "Phone Verification",
			Text:    "Your phone verification code is: {{.Passcode}}",
		})
	}
}

// WithEmailVerificationTemplate registers the email verification template
func WithEmailVerificationTemplate() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		return nm.RegisterNotification(EmailVerification, notification.EmailSystem, notification.NoticeTemplate{
			Subject: "Verify Your Email Address",
			Html:    loadTemplate("templates/email/email_verification.html"),
		})
	}
}

// WithDefaultTemplates registers all default notification templates
func WithDefaultTemplates() NotificationManagerOption {
	return func(nm *notification.NotificationManager) error {
		options := []NotificationManagerOption{
			WithUsernameReminderTemplate(),
			WithPasswordResetTemplate(),
			WithTwofaCodeEmailTemplate(),
			WithMagicLinkLoginTemplate(),
			WithTwofaCodeSmsTemplate(),
			WithPhoneVerificationTemplate(),
			WithEmailVerificationTemplate(),
		}

		for _, opt := range options {
			if err := opt(nm); err != nil {
				return err
			}
		}

		return nil
	}
}

// NewNotificationManager creates a new notification manager with the provided options
func NewNotificationManager(baseUrl string, opts ...NotificationManagerOption) (*notification.NotificationManager, error) {
	notificationManager := notification.NewNotificationManager(baseUrl)

	// Apply all options
	for _, opt := range opts {
		if err := opt(notificationManager); err != nil {
			return nil, err
		}
	}

	return notificationManager, nil
}

// For backward compatibility
func NewNotificationManagerWithConfigs(baseUrl string, smtpConfig notification.SMTPConfig, twConfig notification.TwilioConfig) (*notification.NotificationManager, error) {
	return NewNotificationManager(
		baseUrl,
		WithSMTP(smtpConfig),
		WithTwilio(twConfig),
		WithDefaultTemplates(),
	)
}
