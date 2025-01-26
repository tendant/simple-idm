package email

import (
	"fmt"

	"github.com/wneessen/go-mail"
)

// Config holds email service configuration
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Service provides email sending functionality
type Service struct {
	config Config
	client *mail.Client
}

// NewService creates a new email service instance
func NewService(config Config) (*Service, error) {
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

	return &Service{
		config: config,
		client: client,
	}, nil
}

// SendEmail sends an email with the given parameters
func (s *Service) SendEmail(to, subject, body string) error {
	// Create a new message
	msg := mail.NewMsg()
	if err := msg.From(s.config.From); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("failed to set to address: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, body)

	// Send the email
	if err := s.client.Send(msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendUsernameReminder sends an email with the user's username
func (s *Service) SendUsernameReminder(to, username string) error {
	subject := "Your Username Reminder"
	body := fmt.Sprintf(`
		<html>
			<body>
				<h2>Username Reminder</h2>
				<p>Hello,</p>
				<p>You recently requested to be reminded of your username.</p>
				<p>Your username is: <strong>%s</strong></p>
				<p>You can use this username to log in to your account.</p>
				<p>If you did not request this reminder, please ignore this email.</p>
				<br>
				<p>Best regards,</p>
				<p>Your IDM Team</p>
			</body>
		</html>
	`, username)

	return s.SendEmail(to, subject, body)
}

// SendPasswordResetLink sends an email with a password reset link
func (s *Service) SendPasswordResetLink(to, resetLink string) error {
	subject := "Password Reset Request"
	body := fmt.Sprintf(`
		<html>
			<body>
				<h2>Password Reset Request</h2>
				<p>Hello,</p>
				<p>You recently requested to reset your password.</p>
				<p>Click the link below to reset your password:</p>
				<p><a href="%s">Reset Password</a></p>
				<p>If you did not request a password reset, please ignore this email.</p>
				<br>
				<p>Best regards,</p>
				<p>Your IDM Team</p>
			</body>
		</html>
	`, resetLink)

	return s.SendEmail(to, subject, body)
}
