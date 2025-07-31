package notification

import (
	"fmt"
	"log/slog"

	twclient "github.com/torpago/notice-proc/twsms"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

type SMSNotifier struct {
	client       *twclient.TwSmsClient
	TwilioConfig TwilioConfig
}

type TwilioConfig struct {
	TwilioAccountSid string `env:"TWILIO_ACCOUNT_SID"`
	TwilioAuthToken  string `env:"TWILIO_AUTH_TOKEN"`
	TwilioFrom       string `env:"TWILIO_FROM" env-default:"+15005550006"`
}

func NewSMSNotifier(config TwilioConfig) *SMSNotifier {
	client := twilio.NewRestClient()
	return &SMSNotifier{
		client: &twclient.TwSmsClient{
			Client: client,
			From:   config.TwilioFrom,
		},
		TwilioConfig: config,
	}
}

func (s *SMSNotifier) Send(noticeType NoticeType, notification NotificationData, template NoticeTemplate) error {
	if notification.To == "" || notification.Body == "" {
		return fmt.Errorf("SMS notification requires 'To' and 'Body'")
	}

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(notification.To)
	params.SetFrom(s.TwilioConfig.TwilioFrom)
	params.SetBody(notification.Body)

	resp, err := s.client.Client.Api.CreateMessage(params)

	if err != nil {
		return err
	} else {
		slog.Info("Successfully sent sms to: ", "to", notification.To, "response", resp)
		return nil
	}
}
