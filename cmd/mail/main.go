package main

import (
	"crypto/tls"
	"log"

	"github.com/wneessen/go-mail"
)

func main() {
	message := mail.NewMsg()
	if err := message.From("toni.sender@example.com"); err != nil {
		log.Fatalf("failed to set From address: %s", err)
	}
	if err := message.To("tina.recipient@example.com"); err != nil {
		log.Fatalf("failed to set To address: %s", err)
	}
	message.Subject("This is my first mail with go-mail!")
	message.SetBodyString(mail.TypeTextPlain, "Do you like this mail? I certainly do!")
	client, err := mail.NewClient("localhost", mail.WithPort(1025),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername("noreply@example.com"), mail.WithPassword("pwd"),
		mail.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
		mail.WithTLSPolicy(mail.NoTLS),
	)
	client.SetSSL(false)
	if err != nil {
		log.Fatalf("failed to create mail client: %s", err)
	}
	if err := client.DialAndSend(message); err != nil {
		log.Fatalf("failed to send mail: %s", err)
	}
}
