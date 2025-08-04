package notification

import (
	"fmt"
	"log/slog"
)

// NotificationSystem represents a type of notification system (e.g., email, SMS, Slack).
type NotificationSystem string

// NoticeType represents a type of notification (e.g., "welcome", "password_reset").
type NoticeType string

const (
	EmailSystem      NotificationSystem = "email"
	SMSSystem        NotificationSystem = "sms"
	SlackSystem      NotificationSystem = "slack"
	CloudEventSystem NotificationSystem = "cloudevent"

	ExampleNotice          NoticeType = "example"
	PasswordResetNotice    NoticeType = "password_reset"
	PasswordUpdateNotice   NoticeType = "password_update"
	UsernameReminderNotice NoticeType = "username_reminder"
)

type NoticeTemplate struct {
	Subject string
	Text    string // Plain text version of the notification
	Html    string // HTML version of the notification
}

// NotificationManager manages notifiers and notification templates.
type NotificationManager struct {
	BaseUrl              string
	notifiers            map[NotificationSystem]Notifier                      // Map of notification systems to their Notifier implementations
	notificationRegistry map[NoticeType]map[NotificationSystem]NoticeTemplate // Registry for notification templates
}

// NewNotificationManager creates and returns a new NotificationManager.
func NewNotificationManager(baseUrl string) *NotificationManager {
	return &NotificationManager{
		BaseUrl:              baseUrl,
		notifiers:            make(map[NotificationSystem]Notifier),
		notificationRegistry: make(map[NoticeType]map[NotificationSystem]NoticeTemplate),
	}
}

// RegisterNotifier registers a notifier for a specific system.
func (nm *NotificationManager) RegisterNotifier(system NotificationSystem, notifier Notifier) {
	nm.notifiers[system] = notifier
}

// RegisterNotification dynamically adds a notification template to the registry.
func (nm *NotificationManager) RegisterNotification(noticeType NoticeType, system NotificationSystem, template NoticeTemplate) error {
	// Validate input
	if noticeType == "" || system == "" || template.Subject == "" || (template.Text == "" && template.Html == "") {
		return fmt.Errorf("invalid input: notification type, system, subject, and at least one of text or html content must be provided")
	}

	// Check if the notification type exists in the registry
	if _, exists := nm.notificationRegistry[noticeType]; !exists {
		nm.notificationRegistry[noticeType] = make(map[NotificationSystem]NoticeTemplate)
	}

	// Add or update the template for the system under the given notification type
	nm.notificationRegistry[noticeType][system] = template
	return nil
}

// Send sends a notification to all systems registered for the specified notification type.
func (nm *NotificationManager) Send(noticeType NoticeType, notification NotificationData) error {
	// Check if the notification type exists in the registry
	systemTemplates, exists := nm.notificationRegistry[noticeType]
	if !exists {
		return fmt.Errorf("no templates registered for notification type: %s", noticeType)
	}

	var lastError error
	notifierFound := false

	// Iterate through all systems registered for the notification type
	for system, template := range systemTemplates {
		// Get the notifier for the current system
		notifier, notifierExists := nm.notifiers[system]
		if !notifierExists {
			lastError = fmt.Errorf("no notifier registered for system: %s", system)
			continue
		}

		notifierFound = true

		// Render the template (if applicable)
		slog.Info("Using template for system", "system", system, "subject", template.Subject)

		// Send the notification using the notifier
		err := notifier.Send(noticeType, notification, template)
		if err != nil {
			// Log the error and store it as the last error (if any)
			slog.Info("Error sending notification", "system", system, "err", err)
			lastError = err
		}
	}

	if !notifierFound {
		return lastError
	}

	// Return the last error if any occurred during the process
	return lastError
}
