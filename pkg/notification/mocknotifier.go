package notification

type MockNotifier struct {
    SentNotifications []NotificationData
}

func (m *MockNotifier) Send(notification NotificationData) error {
    m.SentNotifications = append(m.SentNotifications, notification)
    return nil
}