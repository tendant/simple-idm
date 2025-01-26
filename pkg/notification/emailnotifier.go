package notification

import (
	"fmt"

	"github.com/wneessen/go-mail"
)

type EmailNotifier struct {
	SMTPConfig SMTPConfig // SMTP server configuration
	client     *mail.Client
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
}

func NewEmailNotifier(config SMTPConfig) (*EmailNotifier, error) {
	// Create mail client
	client, err := mail.NewClient(config.Host,
		mail.WithPort(config.Port),
		mail.WithUsername(config.Username),
		mail.WithPassword(config.Password),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail client: %w", err)
	}
	return &EmailNotifier{SMTPConfig: config, client: client}, nil

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

// SendEmail sends an email with the given parameters
func (e *EmailNotifier) SendEmail(to, subject, body string) error {
	// Create a new message
	msg := mail.NewMsg()
	if err := msg.From(e.SMTPConfig.Username); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("failed to set to address: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, body)

	// Send the email
	if err := e.client.Send(msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
