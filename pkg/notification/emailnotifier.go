package notification

import (
	"bytes"
	"fmt"
	"html/template"
	"os"

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

	// Read template file
	templateContent := noticeTemplate.Body
	if templateContent == "" {
		content, err := os.ReadFile(noticeTemplate.BodyPath)
		if err != nil {
			return fmt.Errorf("failed to read template file: %v", err)
		}
		templateContent = string(content)
	}

	// Parse and execute the template
	tmpl, err := template.New("email").Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var body bytes.Buffer
	err = tmpl.Execute(&body, notification)
	if err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
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
	msg.SetBodyString(mail.TypeTextHTML, body.String())

	// Send the email
	if err := e.client.Send(msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	fmt.Printf("Email sent successfully to %s via SMTP %s:%d\n", notification.To, e.SMTPConfig.Host, e.SMTPConfig.Port)
	return nil
}
