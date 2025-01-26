package notification

import (
	"fmt"
)

type EmailNotifier struct {
	SMTPConfig SMTPConfig // SMTP server configuration
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
}

func NewEmailNotifier(config SMTPConfig) *EmailNotifier {
	return &EmailNotifier{SMTPConfig: config}
}

func (e *EmailNotifier) Send(notificationType NotificationType, notification NotificationData) error {
	if notification.To == "" || notification.Body == "" {
		return fmt.Errorf("email notification requires 'To' and 'Body'")
	}
	fmt.Printf("Sending Email to %s via SMTP %s:%d\n", notification.To, e.SMTPConfig.Host, e.SMTPConfig.Port)
	fmt.Printf("Subject: %s\n", notification.Subject)
	fmt.Printf("Body: %s\n", notification.Body)
	// Add actual SMTP logic here
	return nil
}
