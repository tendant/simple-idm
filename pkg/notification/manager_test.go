package notification

import (
	"testing"
)

func TestNewNotificationManager(t *testing.T) {
	nm := NewNotificationManager("")
	if nm == nil {
		t.Error("NewNotificationManager returned nil")
	}
	if nm.notifiers == nil {
		t.Error("notifiers map not initialized")
	}
	if nm.notificationRegistry == nil {
		t.Error("notificationRegistry map not initialized")
	}
}

func TestRegisterNotifier(t *testing.T) {
	nm := NewNotificationManager("")
	mockNotifier := &MockNotifier{}

	// Test registering a notifier
	nm.RegisterNotifier(EmailSystem, mockNotifier)
	if n, exists := nm.notifiers[EmailSystem]; !exists {
		t.Error("Notifier not registered")
	} else if n != mockNotifier {
		t.Error("Wrong notifier registered")
	}

	// Test overwriting existing notifier
	newMockNotifier := &MockNotifier{}
	nm.RegisterNotifier(EmailSystem, newMockNotifier)
	if n := nm.notifiers[EmailSystem]; n != newMockNotifier {
		t.Error("Notifier not overwritten")
	}
}

func TestRegisterNotification(t *testing.T) {
	nm := NewNotificationManager("")

	tests := []struct {
		name        string
		notifType   NoticeType
		system      NotificationSystem
		template    NoticeTemplate
		shouldError bool
	}{
		{
			name:        "Valid registration with both Text and Html",
			notifType:   ExampleNotice,
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "Example Email", Text: "This is an example email", Html: "<p>This is an example email</p>"},
			shouldError: false,
		},
		{
			name:        "Valid registration with Text only",
			notifType:   ExampleNotice,
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "Example Email", Text: "This is an example email"},
			shouldError: false,
		},
		{
			name:        "Valid registration with Html only",
			notifType:   ExampleNotice,
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "Example Email", Html: "<p>This is an example email</p>"},
			shouldError: false,
		},
		{
			name:        "Empty notification type",
			notifType:   "",
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "Example Email", Text: "This is an example email"},
			shouldError: true,
		},
		{
			name:        "Empty system",
			notifType:   ExampleNotice,
			system:      "",
			template:    NoticeTemplate{Subject: "Example Email", Text: "This is an example email"},
			shouldError: true,
		},
		{
			name:        "Empty template",
			notifType:   ExampleNotice,
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "", Text: "", Html: ""},
			shouldError: true,
		},
		{
			name:        "Empty subject",
			notifType:   ExampleNotice,
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "", Text: "This is an example email"},
			shouldError: true,
		},
		{
			name:        "No content",
			notifType:   ExampleNotice,
			system:      EmailSystem,
			template:    NoticeTemplate{Subject: "Example Email", Text: "", Html: ""},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := nm.RegisterNotification(tt.notifType, tt.system, tt.template)
			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.shouldError {
				if template, exists := nm.notificationRegistry[tt.notifType][tt.system]; !exists {
					t.Error("Template not registered")
				} else if template.Subject != tt.template.Subject {
					t.Errorf("Wrong subject registered. Got %s, want %s", template.Subject, tt.template.Subject)
				} else if template.Text != tt.template.Text {
					t.Errorf("Wrong text body registered. Got %s, want %s", template.Text, tt.template.Text)
				} else if template.Html != tt.template.Html {
					t.Errorf("Wrong HTML body registered. Got %s, want %s", template.Html, tt.template.Html)
				}
			}
		})
	}
}

func TestSend(t *testing.T) {
	nm := NewNotificationManager("")
	mockEmailNotifier := &MockNotifier{}
	mockSMSNotifier := &MockNotifier{}

	// Register notifiers
	nm.RegisterNotifier(EmailSystem, mockEmailNotifier)
	nm.RegisterNotifier(SMSSystem, mockSMSNotifier)

	// Register notifications
	err := nm.RegisterNotification(ExampleNotice, EmailSystem, NoticeTemplate{Subject: "Example Notification", Text: "This is an example notification", Html: "<p>This is an example notification</p>"})
	if err != nil {
		t.Fatalf("Failed to register email notification: %v", err)
	}
	err = nm.RegisterNotification(ExampleNotice, SMSSystem, NoticeTemplate{Subject: "Example Notification", Html: "templates/example_sms.tmpl"})
	if err != nil {
		t.Fatalf("Failed to register SMS notification: %v", err)
	}

	// Test sending notification
	testData := NotificationData{
		To:      "user@example.com",
		Subject: "Test Subject",
		Body:    "Test Body",
	}

	err = nm.Send(ExampleNotice, testData)
	if err != nil {
		t.Errorf("Failed to send notification: %v", err)
	}

	// Verify email notification was sent
	if len(mockEmailNotifier.SentNotifications) != 1 {
		t.Error("Email notification not sent")
	} else {
		sent := mockEmailNotifier.SentNotifications[0]
		if sent.To != testData.To || sent.Subject != testData.Subject || sent.Body != testData.Body {
			t.Error("Email notification data mismatch")
		}
	}

	// Verify SMS notification was sent
	if len(mockSMSNotifier.SentNotifications) != 1 {
		t.Error("SMS notification not sent")
	} else {
		sent := mockSMSNotifier.SentNotifications[0]
		if sent.To != testData.To || sent.Subject != testData.Subject || sent.Body != testData.Body {
			t.Error("SMS notification data mismatch")
		}
	}
}

func TestSendErrors(t *testing.T) {
	nm := NewNotificationManager("")

	// Test sending with unregistered notification type
	err := nm.Send("unregistered", NotificationData{})
	if err == nil {
		t.Error("Expected error for unregistered notification type")
	}

	// Register notification without registering notifier
	err = nm.RegisterNotification(ExampleNotice, EmailSystem, NoticeTemplate{Subject: "Example Notification", Html: "templates/example_email.tmpl"})
	if err != nil {
		t.Fatalf("Failed to register notification: %v", err)
	}

	// Test sending with missing notifier
	err = nm.Send(ExampleNotice, NotificationData{})
	if err == nil {
		t.Error("Expected error for missing notifier")
	} else if err.Error() != "no notifier registered for system: email" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
