package notification

import (
    "fmt"
)

type NotificationManager struct {
    notifiers map[string]Notifier // Map system name (e.g., "email") to Notifier
}

func NewNotificationManager() *NotificationManager {
    return &NotificationManager{
        notifiers: make(map[string]Notifier),
    }
}

func (nm *NotificationManager) RegisterNotifier(system string, notifier Notifier) {
    nm.notifiers[system] = notifier
}

func (nm *NotificationManager) Send(system string, notification NotificationData) error {
    notifier, exists := nm.notifiers[system]
    if !exists {
        return fmt.Errorf("no notifier registered for system: %s", system)
    }
    return notifier.Send(notification)
}