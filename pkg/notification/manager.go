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
	notifiers            map[NotificationSystem]Notifier                               // Map of notification systems to their Notifier implementations
	notificationRegistry map[NotificationType]map[NotificationSystem]map[string]string // Registry for notification templates
}

// NewNotificationManager creates and returns a new NotificationManager.
func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		notifiers:            make(map[NotificationSystem]Notifier),
		notificationRegistry: make(map[NotificationType]map[NotificationSystem]map[string]string),
	}
}

// RegisterNotifier registers a notifier for a specific system.
func (nm *NotificationManager) RegisterNotifier(system NotificationSystem, notifier Notifier) {
	nm.notifiers[system] = notifier
}

// RegisterNotification dynamically adds a notification template to the registry.
func (nm *NotificationManager) RegisterNotification(notifType NotificationType, system NotificationSystem, subject string, templatePath string) error {
	// Validate input
	if notifType == "" || system == "" || templatePath == "" || subject == "" {
		return fmt.Errorf("invalid input: notification type, system, subject, and templatePath cannot be empty")
	}

	// Check if the notification type exists in the registry
	if _, exists := nm.notificationRegistry[notifType]; !exists {
		nm.notificationRegistry[notifType] = make(map[NotificationSystem]map[string]string)
	}

	// Add or update the template for the system under the given notification type
	nm.notificationRegistry[notifType][system] = map[string]string{"subject": subject, "template": templatePath}
	return nil
}

// Send sends a notification to all systems registered for the specified notification type.
func (nm *NotificationManager) Send(notifType NotificationType, notification NotificationData) error {
	// Check if the notification type exists in the registry
	systemTemplates, exists := nm.notificationRegistry[notifType]
	if !exists {
		return fmt.Errorf("no templates registered for notification type: %s", notifType)
	}

	var lastError error
	notifierFound := false

	// Iterate through all systems registered for the notification type
	for system, templatePath := range systemTemplates {
		// Get the notifier for the current system
		notifier, notifierExists := nm.notifiers[system]
		if !notifierExists {
			lastError = fmt.Errorf("no notifier registered for system: %s", system)
			continue
		}

		notifierFound = true

		// Render the template (if applicable)
		fmt.Printf("Using template for system %s: %s\n", system, templatePath)

		// Send the notification using the notifier
		err := notifier.Send(notifType, notification)
		if err != nil {
			// Log the error and store it as the last error (if any)
			fmt.Printf("Error sending notification via %s: %v\n", system, err)
			lastError = err
		}
	}

	if !notifierFound {
		return lastError
	}

	// Return the last error if any occurred during the process
	return lastError
}
