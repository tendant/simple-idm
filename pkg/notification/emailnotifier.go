package notification

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log/slog"

	"github.com/wneessen/go-mail"
)

type SMTPConfig struct {
	Host     string
	Port     int
	TLS      bool
	Username string
	Password string
	From     string
}

type EmailNotifier struct {
	SMTPConfig SMTPConfig
	client     *mail.Client
	opts       []mail.Option
}

func NewEmailNotifier(config SMTPConfig) (*EmailNotifier, error) {
	// Create mail client options
	opts := []mail.Option{
		mail.WithPort(config.Port),
		mail.WithTimeout(30), // Set timeout to 30 seconds
	}

	// Only add authentication if username and password are provided
	if config.Username != "" && config.Password != "" {
		slog.Info("Adding authentication", "user", config.Username)
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthLogin), // Changed from PLAIN to LOGIN
			mail.WithUsername(config.Username),
			mail.WithPassword(config.Password),
		)
	}

	// Configure TLS settings
	if !config.TLS {
		slog.Info("Using NoTLS policy")
		opts = append(opts,
			mail.WithTLSConfig(&tls.Config{
				InsecureSkipVerify: true, // Skip hostname verification
			}),
			mail.WithTLSPolicy(mail.NoTLS),
		)
	} else {
		slog.Info("Using TLS Mandatory policy")
		opts = append(opts,
			mail.WithTLSConfig(&tls.Config{
				InsecureSkipVerify: true,
			}),
			mail.WithTLSPolicy(mail.TLSMandatory),
		)
	}

	slog.Info("Creating mail client", "Host", config.Host, "Port", config.Port)
	client, err := mail.NewClient(config.Host, opts...)
	if err != nil {
		slog.Error("Failed to create mail client", "err", err)
		return nil, err
	}

	return &EmailNotifier{SMTPConfig: config, client: client, opts: opts}, nil
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
	if err := e.client.DialAndSend(msg); err != nil {
		slog.Error("Failed to send email", "err", err)
		return err
	}

	slog.Info("Email sent successfully", "to", notification.To, "host", e.SMTPConfig.Host, "port", e.SMTPConfig.Port)
	return nil
}
