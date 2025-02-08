package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/wneessen/go-mail"
	maillog "github.com/wneessen/go-mail/log"
)

//	go run cmd/emailtest/main.go \
//	  -host smtp.gmail.com \
//	  -port 587 \
//	  -user your.email@gmail.com \
//	  -pass "your-app-specific-password" \
//	  -from your.email@gmail.com \
//	  -to recipient@example.com
//
// MailLogger is a wrapper for slog.Logger that implements go-mail's Logger interface
type MailLogger struct {
	logger *slog.Logger
}

func (l *MailLogger) Debugf(log maillog.Log) {
	l.logger.Debug(fmt.Sprintf(log.Format, log.Messages...))
}

func (l *MailLogger) Infof(log maillog.Log) {
	l.logger.Info(fmt.Sprintf(log.Format, log.Messages...))
}

func (l *MailLogger) Warnf(log maillog.Log) {
	l.logger.Warn(fmt.Sprintf(log.Format, log.Messages...))
}

func (l *MailLogger) Errorf(log maillog.Log) {
	l.logger.Error(fmt.Sprintf(log.Format, log.Messages...))
}

func main() {
	// Parse command line flags
	host := flag.String("host", "localhost", "SMTP server host")
	port := flag.Int("port", 1025, "SMTP server port")
	username := flag.String("user", "noreply@example.com", "SMTP username")
	password := flag.String("pass", "pwd", "SMTP password")
	from := flag.String("from", "noreply@example.com", "From email address")
	to := flag.String("to", "test@example.com", "To email address")
	flag.Parse()

	if *from == "" || *to == "" {
		fmt.Println("Error: from and to email addresses are required")
		os.Exit(1)
	}

	// Create a logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	mailLogger := &MailLogger{logger: logger}

	// Create client options
	opts := []mail.Option{
		mail.WithPort(1025),
		// mail.WithTimeout(30), // Set timeout to 30 seconds
		mail.WithDebugLog(), // Enable debug logging
		mail.WithLogger(mailLogger),
	}

	// Add authentication if provided
	if *username != "" && *password != "" {
		slog.Info("Adding authentication", "user", *username, "pass", *password)
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername("noreply@example.com"),
			mail.WithPassword("pwd"),
		)
	}

	// For production SMTP servers (not local testing)
	opts = append(opts,
		mail.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
		mail.WithTLSPolicy(mail.NoTLS))

	// Create new mail client
	client, err := mail.NewClient("localhost", opts...)
	client.SetSSL(false)
	if err != nil {
		slog.Error("Failed to create mail client", "err", err, "host", *host)
		return
	}

	// Create new message
	msg := mail.NewMsg()
	if err := msg.From(*from); err != nil {
		slog.Error("Failed to set From address", "err", err)
		return
	}
	if err := msg.To(*to); err != nil {
		slog.Error("Failed to set To address", "err", err)
		return
	}

	msg.Subject("Test Email from Simple-IDM")
	msg.SetBodyString(mail.TypeTextPlain, "This is a test email from Simple-IDM email testing tool.")

	// Send the email
	if err := client.DialAndSend(msg); err != nil {
		slog.Error("Failed to send email", "err", err,
			"host", *host, "port", *port,
			"username", *username, "password", *password,
			"from", *from, "to", *to,
		)
		return
	}

	slog.Info("Email sent successfully!")
}
