package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/wneessen/go-mail"
)

func main() {
	// Parse command line flags
	host := flag.String("host", "localhost", "SMTP server host")
	port := flag.Int("port", 25, "SMTP server port")
	username := flag.String("user", "", "SMTP username")
	password := flag.String("pass", "", "SMTP password")
	from := flag.String("from", "", "From email address")
	to := flag.String("to", "", "To email address")
	flag.Parse()

	if *from == "" || *to == "" {
		fmt.Println("Error: from and to email addresses are required")
		os.Exit(1)
	}

	// Create client options
	opts := []mail.Option{
		mail.WithPort(*port),
		mail.WithTimeout(30),              // Set timeout to 30 seconds
		mail.WithHELO("localhost"),        // Use simple HELO
		mail.WithDebugLog(),               // Enable debug logging
		mail.WithoutNoop(),                // Disable NOOP command
		mail.WithTLSConfig(&tls.Config{    // Configure TLS settings
			InsecureSkipVerify: true,      // Skip hostname verification
		}),
	}

	// Add authentication if provided
	if *username != "" && *password != "" {
		opts = append(opts,
			mail.WithUsername(*username),
			mail.WithPassword(*password),
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
		)
	}

	// Create new mail client
	client, err := mail.NewClient(*host, opts...)
	if err != nil {
		log.Fatalf("Failed to create mail client: %v", err)
	}

	// Create new message
	msg := mail.NewMsg()
	if err := msg.From(*from); err != nil {
		log.Fatalf("Failed to set From address: %v", err)
	}
	if err := msg.To(*to); err != nil {
		log.Fatalf("Failed to set To address: %v", err)
	}

	msg.Subject("Test Email from Simple-IDM")
	msg.SetBodyString(mail.TypeTextPlain, "This is a test email from Simple-IDM email testing tool.")

	// Send the email
	if err := client.Send(msg); err != nil {
		log.Fatalf("Failed to send email: %v", err)
	}

	fmt.Println("Email sent successfully!")
}
