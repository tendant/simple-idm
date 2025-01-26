package notification

import (
	"fmt"
)

type NotificationManager struct {
	notifiers map[NotificationSystem]Notifier // Map system name (e.g., "email") to Notifier
}

func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		notifiers: make(map[NotificationSystem]Notifier),
	}
}

func (nm *NotificationManager) RegisterNotifier(system NotificationSystem, notifier Notifier) {
	nm.notifiers[system] = notifier
}

func (nm *NotificationManager) Send(system NotificationSystem, notification NotificationData) error {
	notifier, exists := nm.notifiers[system]
	if !exists {
		return fmt.Errorf("no notifier registered for system: %s", system)
	}
	return notifier.Send(notification)
}
