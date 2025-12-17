package config

import (
	"github.com/tendant/simple-idm/pkg/notification"
)

// EmailConfig holds SMTP email configuration
// This is shared across all services to avoid duplication
type EmailConfig struct {
	Host     string `env:"EMAIL_HOST" env-default:"localhost"`
	Port     uint16 `env:"EMAIL_PORT" env-default:"1025"`
	Username string `env:"EMAIL_USERNAME" env-default:"noreply@example.com"`
	Password string `env:"EMAIL_PASSWORD" env-default:"pwd"`
	From     string `env:"EMAIL_FROM" env-default:"noreply@example.com"`
	TLS      bool   `env:"EMAIL_TLS" env-default:"false"`
}

// ToSMTPConfig converts the config to a notification.SMTPConfig
func (e EmailConfig) ToSMTPConfig() notification.SMTPConfig {
	return notification.SMTPConfig{
		Host:     e.Host,
		Port:     int(e.Port),
		Username: e.Username,
		Password: e.Password,
		From:     e.From,
		TLS:      e.TLS,
	}
}

// NewEmailConfigFromEnv creates an EmailConfig from environment variables
func NewEmailConfigFromEnv() EmailConfig {
	return EmailConfig{
		Host:     GetEnvOrDefault("EMAIL_HOST", "localhost"),
		Port:     GetEnvUint16("EMAIL_PORT", 1025),
		Username: GetEnvOrDefault("EMAIL_USERNAME", "noreply@example.com"),
		Password: GetEnvOrDefault("EMAIL_PASSWORD", "pwd"),
		From:     GetEnvOrDefault("EMAIL_FROM", "noreply@example.com"),
		TLS:      GetEnvBool("EMAIL_TLS", false),
	}
}

// TwilioConfig holds Twilio SMS configuration
type TwilioConfig struct {
	TwilioAccountSid string `env:"TWILIO_ACCOUNT_SID"`
	TwilioAuthToken  string `env:"TWILIO_AUTH_TOKEN"`
	TwilioFrom       string `env:"TWILIO_FROM"`
}

// ToNotificationTwilioConfig converts the config to a notification.TwilioConfig
func (t TwilioConfig) ToNotificationTwilioConfig() notification.TwilioConfig {
	return notification.TwilioConfig{
		TwilioAccountSid: t.TwilioAccountSid,
		TwilioAuthToken:  t.TwilioAuthToken,
		TwilioFrom:       t.TwilioFrom,
	}
}

// IsConfigured returns true if Twilio is configured
func (t TwilioConfig) IsConfigured() bool {
	return t.TwilioAccountSid != "" && t.TwilioAuthToken != "" && t.TwilioFrom != ""
}

// NewTwilioConfigFromEnv creates a TwilioConfig from environment variables
func NewTwilioConfigFromEnv() TwilioConfig {
	return TwilioConfig{
		TwilioAccountSid: GetEnv("TWILIO_ACCOUNT_SID"),
		TwilioAuthToken:  GetEnv("TWILIO_AUTH_TOKEN"),
		TwilioFrom:       GetEnv("TWILIO_FROM"),
	}
}
