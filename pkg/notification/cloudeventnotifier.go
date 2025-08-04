package notification

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tendant/ce-client/ce"
)

const (
	SOURCE = "simple-idm-server"
)

// CloudEventNotifier implements the simple-idm Notifier interface
// for sending cloud events without requiring email addresses
type CloudEventNotifier struct {
	eventClient *ce.EventClient
	source      string
}

// NewCloudEventNotifier creates a new CloudEventNotifier
func NewCloudEventNotifier(ctx context.Context, eventHubURL string, wg *sync.WaitGroup) (*CloudEventNotifier, error) {
	eventClient, err := ce.NewEventClient(ctx, wg, eventHubURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create event client: %w", err)
	}

	return &CloudEventNotifier{
		eventClient: eventClient,
		source:      SOURCE,
	}, nil
}

// Send implements the Notifier interface from simple-idm
// It sends cloud events without requiring an email address
func (n *CloudEventNotifier) Send(noticeType NoticeType, data NotificationData, template NoticeTemplate) error {
	// Map simple-idm notification type to cloud event type
	slog.Info("CloudEventNotifier.Send called", "noticeType", noticeType, "template", template.Subject)

	// Create a cloud event
	eventData := ce.EventGeneric{
		Subject: mapNoticeTypeToEventSubject(noticeType),
		Source:  n.source,
		Type:    mapNoticeTypeToEventType(noticeType),
		Data:    make(map[string]interface{}),
	}

	// Add all data from notification.Data to eventData.Data
	for k, v := range data.Data {
		eventData.Data[k] = v
	}

	// Log the event being sent
	slog.Info("Sending cloud event", "eventType", eventData.Type, "subject", eventData.Subject, "source", eventData.Source)
	slog.Info("Cloud event data", "data", eventData.Data)

	// Send the event
	err := n.eventClient.SendEventAsync(eventData)
	if err != nil {
		slog.Error("Failed to send cloud event", "err", err, "noticeType", noticeType)
		return err
	}

	slog.Info("Successfully sent cloud event", "noticeType", noticeType)
	return nil
}

// mapNoticeTypeToEventType maps notification types to cloud event types
func mapNoticeTypeToEventType(noticeType NoticeType) string {
	// Map notification types to event types
	// FIX-ME: Add mapping logic for other notice types as needed
	switch noticeType {
	case TwofaCodeNoticeEmail:
		return string(TwofaCodeNoticeEmail)
	case TwofaCodeNoticeSms:
		return string(TwofaCodeNoticeSms)
	case PhoneVerificationNotice:
		return string(PhoneVerificationNotice)
	default:
		return ""
	}
}

func mapNoticeTypeToEventSubject(noticeType NoticeType) string {
	// Map notification types to event types
	// FIX-ME: Add mapping logic for other notice types as needed
	switch noticeType {
	case TwofaCodeNoticeEmail:
		return string(TwofaCodeNoticeEmail)
	case TwofaCodeNoticeSms:
		return string(TwofaCodeNoticeSms)
	case PhoneVerificationNotice:
		return string(PhoneVerificationNotice)
	default:
		return ""
	}
}
