package notification

import (
	"fmt"
)

// NotificationSystem represents a type of notification system (e.g., email, SMS, Slack).
type NotificationSystem string

// NotificationType represents a type of notification (e.g., "welcome", "password_reset").
type NotificationType string

const (
	EmailSystem NotificationSystem = "email"
	SMSSystem   NotificationSystem = "sms"
	SlackSystem NotificationSystem = "slack"

	ExampleNotification NotificationType = "example"
)

// NotificationManager manages notifiers and notification templates.
type NotificationManager struct {
	notifiers            map[NotificationSystem]Notifier                    // Map of notification systems to their Notifier implementations
	notificationRegistry map[NotificationType]map[NotificationSystem]string // Registry for notification templates
}

// NewNotificationManager creates and returns a new NotificationManager.
func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		notifiers:            make(map[NotificationSystem]Notifier),
		notificationRegistry: make(map[NotificationType]map[NotificationSystem]string),
	}
}

// RegisterNotifier registers a notifier for a specific system.
func (nm *NotificationManager) RegisterNotifier(system NotificationSystem, notifier Notifier) {
	nm.notifiers[system] = notifier
}

// RegisterNotification dynamically adds a notification template to the registry.
func (nm *NotificationManager) RegisterNotification(notifType NotificationType, system NotificationSystem, templatePath string) error {
	// Validate input
	if notifType == "" || system == "" || templatePath == "" {
		return fmt.Errorf("invalid input: notification type, system, and templatePath cannot be empty")
	}

	// Check if the notification type exists in the registry
	if _, exists := nm.notificationRegistry[notifType]; !exists {
		nm.notificationRegistry[notifType] = make(map[NotificationSystem]string)
	}

	// Add or update the template for the system under the given notification type
	nm.notificationRegistry[notifType][system] = templatePath
	return nil
}

// Send sends a notification using the specified system and type.
func (nm *NotificationManager) Send(notifType NotificationType, system NotificationSystem, notification NotificationData) error {
	// Check if the template exists for the notification type and system
	systemTemplates, exists := nm.notificationRegistry[notifType]
	if !exists {
		return fmt.Errorf("no templates registered for notification type: %s", notifType)
	}

	templatePath, exists := systemTemplates[system]
	if !exists {
		return fmt.Errorf("no template registered for system: %s under notification type: %s", system, notifType)
	}

	// Get the notifier for the system
	notifier, exists := nm.notifiers[system]
	if !exists {
		return fmt.Errorf("no notifier registered for system: %s", system)
	}

	// Here, you would typically render the template using the templatePath and data
	fmt.Printf("Using template: %s\n", templatePath)

	// Send the notification using the notifier
	return notifier.Send(notification)
}
