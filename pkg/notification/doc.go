// Package notification provides a unified interface for sending notifications via multiple channels.
//
// This package defines the Notifier interface and provides implementations for email (SMTP),
// SMS (Twilio), and Slack notifications. It's designed to be extensible, allowing custom
// notifier implementations for other channels.
//
// # Features
//
//   - Unified Notifier interface for all notification types
//   - Email via SMTP (with TLS support)
//   - SMS via Twilio
//   - Slack webhooks
//   - HTML and plain text email templates
//   - CC/BCC support for emails
//   - Mock notifier for testing
//   - Template-based notifications
//
// # Core Interface
//
//	type Notifier interface {
//	    Send(noticeType NoticeType, data NotificationData, template NoticeTemplate) error
//	}
//
// All notifiers implement this interface, making them interchangeable.
//
// # Email Notifications (SMTP)
//
// ## Basic Setup
//
//	import "github.com/tendant/simple-idm/pkg/notification"
//
//	// Configure SMTP
//	smtpConfig := notification.SMTPConfig{
//	    Host:     "smtp.gmail.com",
//	    Port:     587,
//	    TLS:      true,
//	    Username: "your-email@gmail.com",
//	    Password: "your-app-password",  // Use app password, not account password
//	    From:     "noreply@example.com",
//	}
//
//	// Create email notifier
//	emailNotifier, err := notification.NewEmailNotifier(smtpConfig)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// ## Sending Email
//
//	// Define notification data
//	data := notification.NotificationData{
//	    To:      "user@example.com",
//	    Subject: "Welcome to Our Service",
//	    Body:    "Thank you for signing up!",
//	    Data: map[string]string{
//	        "username": "john_doe",
//	        "verificationLink": "https://example.com/verify?token=abc123",
//	    },
//	}
//
//	// Define template
//	template := notification.NoticeTemplate{
//	    Subject: "Welcome {{.username}}",
//	    Text:    "Click here to verify: {{.verificationLink}}",
//	    Html:    "<h1>Welcome {{.username}}</h1><a href='{{.verificationLink}}'>Verify Email</a>",
//	}
//
//	// Send email
//	err = emailNotifier.Send(notification.EmailType, data, template)
//	if err != nil {
//	    log.Printf("Failed to send email: %v", err)
//	}
//
// ## Email with CC and BCC
//
//	data := notification.NotificationData{
//	    To: "primary@example.com",
//	    Data: map[string]string{
//	        "cc":  "manager@example.com, admin@example.com",  // Comma-separated
//	        "bcc": "audit@example.com",
//	    },
//	}
//
//	emailNotifier.Send(notification.EmailType, data, template)
//
// ## HTML Email with Fallback
//
// When both Text and Html are provided, email clients can choose:
//   - Plain text clients: Show Text
//   - HTML clients: Show Html
//
//	template := notification.NoticeTemplate{
//	    Subject: "Password Reset",
//	    Text: `
//	Hello {{.username}},
//
//	Click this link to reset your password:
//	{{.resetLink}}
//
//	This link expires in 1 hour.
//	`,
//	    Html: `
//	<!DOCTYPE html>
//	<html>
//	<body style="font-family: Arial, sans-serif;">
//	    <h2>Password Reset</h2>
//	    <p>Hello <strong>{{.username}}</strong>,</p>
//	    <p>Click the button below to reset your password:</p>
//	    <a href="{{.resetLink}}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
//	        Reset Password
//	    </a>
//	    <p style="color: #666; font-size: 12px;">This link expires in 1 hour.</p>
//	</body>
//	</html>
//	`,
//	}
//
// # SMTP Configuration
//
// ## Gmail
//
//	smtpConfig := notification.SMTPConfig{
//	    Host:     "smtp.gmail.com",
//	    Port:     587,  // or 465 for SSL
//	    TLS:      true,
//	    Username: "your-email@gmail.com",
//	    Password: "your-app-password",  // Generate at https://myaccount.google.com/apppasswords
//	    From:     "noreply@yourdomain.com",
//	}
//
// Note: Gmail requires app-specific passwords when 2FA is enabled.
//
// ## SendGrid
//
//	smtpConfig := notification.SMTPConfig{
//	    Host:     "smtp.sendgrid.net",
//	    Port:     587,
//	    TLS:      true,
//	    Username: "apikey",  // Literally "apikey"
//	    Password: "your-sendgrid-api-key",
//	    From:     "noreply@yourdomain.com",
//	}
//
// ## Amazon SES
//
//	smtpConfig := notification.SMTPConfig{
//	    Host:     "email-smtp.us-east-1.amazonaws.com",
//	    Port:     587,
//	    TLS:      true,
//	    Username: "your-smtp-username",  // From SES console
//	    Password: "your-smtp-password",
//	    From:     "noreply@verified-domain.com",  // Must be verified in SES
//	}
//
// ## Local Development (Mailpit)
//
//	smtpConfig := notification.SMTPConfig{
//	    Host:     "localhost",
//	    Port:     1025,
//	    TLS:      false,  // No TLS for local testing
//	    Username: "",     // No auth needed
//	    Password: "",
//	    From:     "dev@localhost",
//	}
//
// Access Mailpit web UI at http://localhost:8025
//
// ## No Authentication (Local SMTP)
//
//	smtpConfig := notification.SMTPConfig{
//	    Host:     "localhost",
//	    Port:     25,
//	    TLS:      false,
//	    Username: "",  // Leave empty for no auth
//	    Password: "",
//	    From:     "noreply@localhost",
//	}
//
// # SMS Notifications (Twilio)
//
// ## Setup
//
//	import "github.com/tendant/simple-idm/pkg/notification"
//
//	// Configure Twilio
//	twilioConfig := notification.TwilioConfig{
//	    AccountSID: "your-account-sid",      // From Twilio console
//	    AuthToken:  "your-auth-token",       // From Twilio console
//	    FromNumber: "+1234567890",           // Your Twilio phone number
//	}
//
//	// Create SMS notifier
//	smsNotifier := notification.NewTwilioSMSNotifier(twilioConfig)
//
// ## Sending SMS
//
//	data := notification.NotificationData{
//	    To:   "+19876543210",  // Recipient's phone number (E.164 format)
//	    Body: "Your verification code is: 123456",
//	}
//
//	template := notification.NoticeTemplate{
//	    Subject: "",  // Not used for SMS
//	    Text:    "Your verification code is: {{.code}}",
//	}
//
//	err = smsNotifier.Send(notification.SMSType, data, template)
//
// # Slack Notifications
//
// ## Setup
//
//	// Configure Slack webhook
//	slackConfig := notification.SlackConfig{
//	    WebhookURL: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
//	}
//
//	slackNotifier := notification.NewSlackNotifier(slackConfig)
//
// ## Sending Messages
//
//	data := notification.NotificationData{
//	    To:   "#general",  // Channel name or webhook channel
//	    Body: "New user registered!",
//	    Data: map[string]string{
//	        "username": "john_doe",
//	        "email":    "john@example.com",
//	    },
//	}
//
//	template := notification.NoticeTemplate{
//	    Text: "New user: {{.username}} ({{.email}})",
//	}
//
//	err = slackNotifier.Send(notification.SlackType, data, template)
//
// # Mock Notifier (Testing)
//
//	// Use mock for unit tests
//	mockNotifier := notification.NewMockNotifier()
//
//	// Send notification (no-op, just logs)
//	mockNotifier.Send(notification.EmailType, data, template)
//
//	// Check if notification was "sent"
//	if len(mockNotifier.SentNotifications) != 1 {
//	    t.Error("Expected 1 notification")
//	}
//
//	// Verify notification contents
//	sent := mockNotifier.SentNotifications[0]
//	if sent.Data.To != "user@example.com" {
//	    t.Errorf("Unexpected recipient: %s", sent.Data.To)
//	}
//
// # Template System
//
// Templates use Go's html/template syntax:
//
//	template := notification.NoticeTemplate{
//	    Subject: "Welcome {{.username}}!",
//	    Text: `
//	Hello {{.username}},
//
//	Your account has been created.
//	Email: {{.email}}
//	Created: {{.createdAt}}
//
//	{{if .hasPassword}}
//	You can log in with your password.
//	{{else}}
//	Please set a password using this link:
//	{{.setPasswordLink}}
//	{{end}}
//	`,
//	}
//
//	data := notification.NotificationData{
//	    To: "user@example.com",
//	    Data: map[string]string{
//	        "username":        "john_doe",
//	        "email":           "john@example.com",
//	        "createdAt":       "2024-01-15",
//	        "hasPassword":     "true",
//	        "setPasswordLink": "https://example.com/set-password?token=xyz",
//	    },
//	}
//
// # Common Patterns
//
// ## Email Verification Flow
//
//	func sendVerificationEmail(email, token string) error {
//	    verifyLink := fmt.Sprintf("https://example.com/verify?token=%s", token)
//
//	    template := notification.NoticeTemplate{
//	        Subject: "Verify Your Email Address",
//	        Html: `
//	<!DOCTYPE html>
//	<html>
//	<body>
//	    <h2>Email Verification</h2>
//	    <p>Click the button below to verify your email address:</p>
//	    <a href="{{.verifyLink}}" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none;">
//	        Verify Email
//	    </a>
//	    <p style="font-size: 12px; color: #666;">
//	        Or copy this link: {{.verifyLink}}
//	    </p>
//	</body>
//	</html>
//	`,
//	        Text: "Verify your email by clicking: {{.verifyLink}}",
//	    }
//
//	    data := notification.NotificationData{
//	        To: email,
//	        Data: map[string]string{
//	            "verifyLink": verifyLink,
//	        },
//	    }
//
//	    return emailNotifier.Send(notification.EmailType, data, template)
//	}
//
// ## Two-Factor Authentication Code
//
//	func send2FACode(phoneNumber, code string) error {
//	    template := notification.NoticeTemplate{
//	        Text: "Your verification code is: {{.code}}\n\nThis code expires in 10 minutes.",
//	    }
//
//	    data := notification.NotificationData{
//	        To: phoneNumber,
//	        Data: map[string]string{
//	            "code": code,
//	        },
//	    }
//
//	    return smsNotifier.Send(notification.SMSType, data, template)
//	}
//
// ## Password Reset
//
//	func sendPasswordReset(email, resetToken string) error {
//	    resetLink := fmt.Sprintf("https://example.com/reset-password?token=%s", resetToken)
//
//	    template := notification.NoticeTemplate{
//	        Subject: "Reset Your Password",
//	        Html: `
//	<!DOCTYPE html>
//	<html>
//	<body style="font-family: Arial;">
//	    <h2>Password Reset Request</h2>
//	    <p>We received a request to reset your password.</p>
//	    <a href="{{.resetLink}}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
//	        Reset Password
//	    </a>
//	    <p style="color: #666; font-size: 12px; margin-top: 20px;">
//	        This link expires in 1 hour.<br>
//	        If you didn't request this, please ignore this email.
//	    </p>
//	</body>
//	</html>
//	`,
//	        Text: "Reset your password: {{.resetLink}}\n\nExpires in 1 hour.",
//	    }
//
//	    data := notification.NotificationData{
//	        To: email,
//	        Data: map[string]string{
//	            "resetLink": resetLink,
//	        },
//	    }
//
//	    return emailNotifier.Send(notification.EmailType, data, template)
//	}
//
// ## Multi-Channel Notification
//
//	// Send notification via multiple channels
//	func notifyUser(user User, message string) error {
//	    template := notification.NoticeTemplate{
//	        Subject: "Important Notification",
//	        Text:    message,
//	        Html:    "<p>" + message + "</p>",
//	    }
//
//	    // Send email
//	    emailData := notification.NotificationData{
//	        To:   user.Email,
//	        Data: map[string]string{"message": message},
//	    }
//	    if err := emailNotifier.Send(notification.EmailType, emailData, template); err != nil {
//	        log.Printf("Email failed: %v", err)
//	    }
//
//	    // Send SMS if user has phone
//	    if user.Phone != "" {
//	        smsData := notification.NotificationData{
//	            To:   user.Phone,
//	            Data: map[string]string{"message": message},
//	        }
//	        if err := smsNotifier.Send(notification.SMSType, smsData, template); err != nil {
//	            log.Printf("SMS failed: %v", err)
//	        }
//	    }
//
//	    return nil
//	}
//
// # Error Handling
//
// Common errors:
//   - "email notification requires 'To' address": No recipient provided
//   - "failed to create mail client": SMTP configuration error
//   - "failed to send email": Network error or SMTP rejection
//   - "failed to parse template": Template syntax error
//   - Authentication failures: Check username/password
//
//	err := emailNotifier.Send(notification.EmailType, data, template)
//	if err != nil {
//	    // Log and handle error
//	    log.Printf("Notification failed: %v", err)
//
//	    // Retry logic
//	    for i := 0; i < 3; i++ {
//	        time.Sleep(time.Second * 2)
//	        if err = emailNotifier.Send(notification.EmailType, data, template); err == nil {
//	            break
//	        }
//	    }
//	}
//
// # Production Best Practices
//
//  1. **Use Environment Variables** for credentials (never commit secrets)
//  2. **Queue Notifications** (use background worker for high volume)
//  3. **Rate Limiting** (respect provider limits: Twilio, SendGrid, etc.)
//  4. **Retry Logic** (with exponential backoff)
//  5. **Logging** (log all sent notifications for auditing)
//  6. **Templates** (store templates in database or files, not code)
//  7. **Monitoring** (track send failures and delivery rates)
//  8. **Testing** (use mock notifier in tests, real SMTP in staging)
//
// # Security Considerations
//
//  1. **TLS**: Always use TLS=true in production SMTP
//  2. **Credentials**: Store in environment variables or secret manager
//  3. **From Address**: Use verified domain to avoid spam filters
//  4. **Rate Limiting**: Prevent abuse (max X emails per user per hour)
//  5. **Content Validation**: Sanitize template data to prevent injection
//  6. **SPF/DKIM**: Configure email authentication records
//
// # Performance
//
//   - Email send: ~500ms-2s (depends on SMTP server)
//   - SMS send: ~1-3s (Twilio API call)
//   - Template parsing: <1ms (cached after first use)
//   - Consider async/queue for non-blocking notifications
//
// # Testing
//
//	import "testing"
//
//	func TestEmailNotification(t *testing.T) {
//	    // Use mock notifier
//	    mockNotifier := notification.NewMockNotifier()
//
//	    data := notification.NotificationData{
//	        To: "test@example.com",
//	        Data: map[string]string{"code": "123456"},
//	    }
//
//	    template := notification.NoticeTemplate{
//	        Subject: "Test",
//	        Text:    "Code: {{.code}}",
//	    }
//
//	    err := mockNotifier.Send(notification.EmailType, data, template)
//	    if err != nil {
//	        t.Fatalf("Send failed: %v", err)
//	    }
//
//	    if len(mockNotifier.SentNotifications) != 1 {
//	        t.Error("Expected 1 notification")
//	    }
//	}
//
// # Dependencies
//
//   - github.com/wneessen/go-mail (SMTP client)
//   - github.com/twilio/twilio-go (Twilio SDK)
//   - Go standard library (html/template, net/http)
//
// # Extending with Custom Notifiers
//
//	// Implement Notifier interface for custom channel
//	type DiscordNotifier struct {
//	    WebhookURL string
//	}
//
//	func (d *DiscordNotifier) Send(noticeType NoticeType, data NotificationData, template NoticeTemplate) error {
//	    // Parse template
//	    tmpl, _ := html.Parse(template.Text)
//	    var buf bytes.Buffer
//	    tmpl.Execute(&buf, data.Data)
//
//	    // Send to Discord webhook
//	    payload := map[string]string{"content": buf.String()}
//	    jsonData, _ := json.Marshal(payload)
//
//	    resp, err := http.Post(d.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
//	    if err != nil {
//	        return err
//	    }
//	    defer resp.Body.Close()
//
//	    if resp.StatusCode != 200 {
//	        return fmt.Errorf("Discord webhook failed: %d", resp.StatusCode)
//	    }
//	    return nil
//	}
//
// Now use DiscordNotifier just like any other notifier!
package notification
