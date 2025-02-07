package notification

import (
	"fmt"
	"log/slog"
)

type SMSNotifier struct {
	APIKey string // API key for SMS provider
}

func NewSMSNotifier(apiKey string) *SMSNotifier {
	return &SMSNotifier{APIKey: apiKey}
}

func (s *SMSNotifier) Send(noticeType NoticeType, notification NotificationData, template NoticeTemplate) error {
	if notification.To == "" || notification.Body == "" {
		return fmt.Errorf("SMS notification requires 'To' and 'Body'")
	}
	slog.Info("Sending SMS via API Key", "To", notification.To)
	slog.Info("Message", "Body", notification.Body)
	// Add actual SMS API logic here
	return nil
}
