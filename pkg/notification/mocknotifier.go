package notification

type MockNotifier struct {
	SentNotifications []NotificationData
}

func (m *MockNotifier) Send(noticeType NoticeType, notification NotificationData, template NoticeTemplate) error {
	m.SentNotifications = append(m.SentNotifications, notification)
	return nil
}
