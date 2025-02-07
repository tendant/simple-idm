package notification

import (
	"fmt"
	"log/slog"
)

type SlackNotifier struct {
	WebhookURL string
}

func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{WebhookURL: webhookURL}
}

func (s *SlackNotifier) Send(noticeType NoticeType, notification NotificationData, template NoticeTemplate) error {
	if notification.Body == "" {
		return fmt.Errorf("slack notification requires 'Body'")
	}
	slog.Info("Sending Slack message to channel via Webhook", "To", notification.To)
	slog.Info("Message:", "Body", notification.Body)
	// Add actual Slack webhook logic here
	return nil
}
