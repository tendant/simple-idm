package notification

import (
	"fmt"
)

type NotificationManager struct {
	notifiers map[NotificationSystem]Notifier // Map system name (e.g., "email") to Notifier
	// NotificationRegistry to store templates
	notificationRegistry map[NotificationType]map[NotificationSystem]string
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

// RegisterNotification dynamically adds a notification template to the registry
func (nm *NotificationManager) RegisterNotification(system NotificationSystem, notifType NotificationType, templatePath string) error {

	// Validate input
	if system == "" || notifType == "" || templatePath == "" {
		return fmt.Errorf("invalid input: system, type, and templatePath cannot be empty")
	}

	// Check if the system exists in the registry
	if _, exists := nm.notificationRegistry[system]; !exists {
		nm.notificationRegistry[system] = make(map[NotificationType]string)
	}
	// Add or update the template for the notification type
	nm.notificationRegistry[system][notifType] = templatePath

	return nil
}
