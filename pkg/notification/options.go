package notification

import (
	"embed"
	"log/slog"
)

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

// NotificationManagerOption is a function that configures a NotificationManager
type NotificationManagerOption func(*NotificationManager) error

// WithSMTP adds an email notifier with the provided SMTP configuration
func WithSMTP(config SMTPConfig) NotificationManagerOption {
	return func(nm *NotificationManager) error {
		emailNotifier, err := NewEmailNotifier(config)
		if err != nil {
			return err
		}
		nm.RegisterNotifier(EmailSystem, emailNotifier)
		return nil
	}
}

// WithTwilio adds an SMS notifier with the provided Twilio configuration
func WithTwilio(config TwilioConfig) NotificationManagerOption {
	return func(nm *NotificationManager) error {
		smsNotifier := NewSMSNotifier(config)
		nm.RegisterNotifier(SMSSystem, smsNotifier)
		return nil
	}
}

// WithUsernameReminderTemplate registers the username reminder template
func WithUsernameReminderTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(UsernameReminder, EmailSystem, NoticeTemplate{
			Subject: "Username Reminder",
			Html:    loadTemplate("templates/email/username_reminder.html"),
		})
	}
}

// WithPasswordResetTemplate registers the password reset template
func WithPasswordResetTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(PasswordResetInit, EmailSystem, NoticeTemplate{
			Subject: "Password Reset Request",
			Html:    loadTemplate("templates/email/password_reset.html"),
		})
	}
}

// WithTwofaCodeEmailTemplate registers the 2FA code email template
func WithTwofaCodeEmailTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(TwofaCodeNoticeEmail, EmailSystem, NoticeTemplate{
			Subject: "2FA Code Init",
			Html:    loadTemplate("templates/email/2fa_code_notice.html"),
		})
	}
}

// WithMagicLinkLoginTemplate registers the magic link login template
func WithMagicLinkLoginTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(MagicLinkLogin, EmailSystem, NoticeTemplate{
			Subject: "Your Login Link",
			Html:    loadTemplate("templates/email/magic_link_login.html"),
		})
	}
}

// WithTwofaCodeSmsTemplate registers the 2FA code SMS template
func WithTwofaCodeSmsTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(TwofaCodeNoticeSms, SMSSystem, NoticeTemplate{
			Subject: "2FA Code Init",
			Text:    "Your 2FA code is: {{.TwofaPasscode}}",
		})
	}
}

// WithPhoneVerificationTemplate registers the phone verification SMS template
func WithPhoneVerificationTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(PhoneVerificationNotice, SMSSystem, NoticeTemplate{
			Subject: "Phone Verification",
			Text:    "Your phone verification code is: {{.Passcode}}",
		})
	}
}

// WithEmailVerificationTemplate registers the email verification template
func WithEmailVerificationTemplate() NotificationManagerOption {
	return func(nm *NotificationManager) error {
		return nm.RegisterNotification(EmailVerification, EmailSystem, NoticeTemplate{
			Subject: "Verify Your Email Address",
			Html:    loadTemplate("templates/email/email_verification.html"),
		})
	}
}

// WithDefaultTemplates registers all default notification templates
func WithDefaultTemplates() NotificationManagerOption {
	return func(nm *NotificationManager) error {
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

// NewNotificationManagerWithOptions creates a new notification manager with the provided options
func NewNotificationManagerWithOptions(baseUrl string, opts ...NotificationManagerOption) (*NotificationManager, error) {
	notificationManager := NewNotificationManager(baseUrl)

	// Apply all options
	for _, opt := range opts {
		if err := opt(notificationManager); err != nil {
			return nil, err
		}
	}

	return notificationManager, nil
}

// NewNotificationManagerWithConfigs creates a notification manager with SMTP and Twilio configs
// For backward compatibility
func NewNotificationManagerWithConfigs(baseUrl string, smtpConfig SMTPConfig, twConfig TwilioConfig) (*NotificationManager, error) {
	return NewNotificationManagerWithOptions(
		baseUrl,
		WithSMTP(smtpConfig),
		WithTwilio(twConfig),
		WithDefaultTemplates(),
	)
}
