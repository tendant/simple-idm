package notification

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"

	"github.com/wneessen/go-mail"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type EmailNotifier struct {
	SMTPConfig SMTPConfig
	client     *mail.Client
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

func (e *EmailNotifier) Send(noticeType NoticeType, notification NotificationData, noticeTemplate NoticeTemplate) error {
	if notification.To == "" {
		return fmt.Errorf("email notification requires 'To' address")
	}

	// Prepare text content if available
	var textBody string
	if noticeTemplate.Text != "" {
		tmpl, err := template.New("text").Parse(noticeTemplate.Text)
		if err != nil {
			return fmt.Errorf("failed to parse text template: %v", err)
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, notification.Data)
		if err != nil {
			return fmt.Errorf("failed to execute text template: %v", err)
		}
		textBody = buf.String()
	}

	// Prepare HTML content if available
	var htmlBody string
	if noticeTemplate.Html != "" {
		tmpl, err := template.New("html").Parse(noticeTemplate.Html)
		if err != nil {
			return fmt.Errorf("failed to parse HTML template: %v", err)
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, notification.Data)
		if err != nil {
			return fmt.Errorf("failed to execute HTML template: %v", err)
		}
		htmlBody = buf.String()
	}
	// Create a new message
	msg := mail.NewMsg()
	if err := msg.From(e.SMTPConfig.From); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	if err := msg.To(notification.To); err != nil {
		return fmt.Errorf("failed to set to address: %w", err)
	}
	msg.Subject(noticeTemplate.Subject)

	// Set text body if available
	if textBody != "" {
		msg.SetBodyString(mail.TypeTextPlain, textBody)
	}

	// Set HTML body if available
	if htmlBody != "" {
		// If we already have a text body, add HTML as alternative
		if textBody != "" {
			msg.AddAlternativeString(mail.TypeTextHTML, htmlBody)
		} else {
			msg.SetBodyString(mail.TypeTextHTML, htmlBody)
		}
	}

	// Send the email
	if err := e.client.Send(msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	slog.Info("Email sent successfully to %s via SMTP", "To", notification.To, "Host", e.SMTPConfig.Host, "Port", e.SMTPConfig.Port)
	return nil
}
