package notification

import (
	"fmt"
)

type NotificationSystem string
type NotificationType string

const (
    EmailSystem NotificationSystem = "email"
    SMSSystem   NotificationSystem = "sms"
    SlackSystem NotificationSystem = "slack"

    ExampleNotification NotificationType = "example"
)

// NotificationRegistry to store templates
var NotificationRegistry = map[NotificationSystem]map[NotificationType]string{}

// RegisterNotification dynamically adds a notification template to the registry
func RegisterNotification(system NotificationSystem, notifType NotificationType, templatePath string) error {

	// Validate input
	if system == "" || notifType == "" || templatePath == "" {
		return fmt.Errorf("invalid input: system, type, and templatePath cannot be empty")
	}
	
	// Check if the system exists in the registry
	if _, exists := NotificationRegistry[system]; !exists {
		NotificationRegistry[system] = make(map[NotificationType]string)
	}
	// Add or update the template for the notification type
	NotificationRegistry[system][notifType] = templatePath

	return nil
}