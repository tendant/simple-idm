package notification

import (
	"fmt"
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
	fmt.Printf("Sending SMS to %s via API Key %s\n", notification.To, s.APIKey)
	fmt.Printf("Message: %s\n", notification.Body)
	// Add actual SMS API logic here
	return nil
}
