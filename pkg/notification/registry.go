package notification

type NotificationSystem string
type NotificationType string

const (
	EmailSystem NotificationSystem = "email"
	SMSSystem   NotificationSystem = "sms"
	SlackSystem NotificationSystem = "slack"

	ExampleNotification NotificationType = "example"
)
