package notification

import "testing"

func TestNotificationManager(t *testing.T) {
    nm := NewNotificationManager()
    mockNotifier := &MockNotifier{}

    nm.RegisterNotifier("mock", mockNotifier)

    notificationData := NotificationData{
        To:   "test@example.com",
        Body: "Test message",
    }

    if err := nm.Send("mock", notificationData); err != nil {
        t.Fatalf("Failed to send notification: %v", err)
    }

    if len(mockNotifier.SentNotifications) != 1 {
        t.Fatalf("Expected 1 notification, got %d", len(mockNotifier.SentNotifications))
    }
}