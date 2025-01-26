package notification

import (
	"fmt"
)

type SlackNotifier struct {
	WebhookURL string
}

func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{WebhookURL: webhookURL}
}

func (s *SlackNotifier) Send(notificationType NotificationType, notification NotificationData) error {
	if notification.Body == "" {
		return fmt.Errorf("Slack notification requires 'Body'")
	}
	fmt.Printf("Sending Slack message to channel: %s via Webhook\n", notification.To)
	fmt.Printf("Message: %s\n", notification.Body)
	// Add actual Slack webhook logic here
	return nil
}
