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
	slog.Info("Created mail client", "Host", config.Host, "Port", config.Port, "Username", config.Username, "Password", config.Password)
	if err != nil {
		slog.Error("Failed to create mail client", "err", err)
		return nil, err

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
			slog.Error("Failed to parse text template", "err", err)
			return err
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, notification.Data)
		if err != nil {
			slog.Error("Failed to execute text template", "err", err)
			return err
		}
		textBody = buf.String()
	}

	// Prepare HTML content if available
	var htmlBody string
	if noticeTemplate.Html != "" {
		tmpl, err := template.New("html").Parse(noticeTemplate.Html)
		if err != nil {
			slog.Error("Failed to parse HTML template", "err", err)
			return err
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, notification.Data)
		if err != nil {
			slog.Error("Failed to execute HTML template", "err", err)
			return err
		}
		htmlBody = buf.String()
	}
	// Create a new message
	msg := mail.NewMsg()
	if err := msg.From(e.SMTPConfig.From); err != nil {
		slog.Error("Failed to set from address", "err", err)
		return err
	}
	if err := msg.To(notification.To); err != nil {
		slog.Error("Failed to set to address", "err", err)
		return err
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
		slog.Error("Failed to send email", "err", err, "client", e.client)
		return err
	}

	slog.Info("Email sent successfully to %s via SMTP", "To", notification.To, "Host", e.SMTPConfig.Host, "Port", e.SMTPConfig.Port)
	return nil
}
