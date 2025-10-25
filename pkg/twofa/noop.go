package twofa

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// NoOpTwoFactorService is a no-op implementation of TwoFactorService.
// This allows services that depend on TwoFactorService to work without
// actual 2FA functionality when 2FA is not needed/configured.
//
// All methods return errors indicating 2FA is not configured.
type NoOpTwoFactorService struct{}

// NewNoOpTwoFactorService creates a new no-op two-factor service.
// Use this when you don't need 2FA functionality.
func NewNoOpTwoFactorService() TwoFactorService {
	return &NoOpTwoFactorService{}
}

func (n *NoOpTwoFactorService) GetTwoFactorSecretByLoginId(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) (string, error) {
	return "", fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) SendTwoFaNotification(ctx context.Context, loginId, userId uuid.UUID, twoFactorType, hashedDeliveryOption string) error {
	return fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) FindTwoFAsByLoginId(ctx context.Context, loginId uuid.UUID) ([]TwoFA, error) {
	return []TwoFA{}, nil // Return empty slice, not an error
}

func (n *NoOpTwoFactorService) FindEnabledTwoFAs(ctx context.Context, loginId uuid.UUID) ([]string, error) {
	return []string{}, nil // Return empty slice, indicating no 2FA methods enabled
}

func (n *NoOpTwoFactorService) EnableTwoFactor(ctx context.Context, loginId uuid.UUID, twoFactorType string) error {
	return fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) DisableTwoFactor(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) error {
	return fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) DeleteTwoFactor(ctx context.Context, params DeleteTwoFactorParams) error {
	return fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) SendTwofaPasscodeEmail(ctx context.Context, email, passcode, username string, userId uuid.UUID) error {
	return fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) SendTwofaPasscodeSms(ctx context.Context, phone, passcode string, userId uuid.UUID) error {
	return fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) Validate2faPasscode(ctx context.Context, loginId uuid.UUID, twoFactorType, passcode string) (bool, error) {
	return false, fmt.Errorf("two-factor authentication not configured")
}

func (n *NoOpTwoFactorService) GenerateTotpQRCode(ctx context.Context, loginId uuid.UUID, issuer, accountName string) (string, string, error) {
	return "", "", fmt.Errorf("two-factor authentication not configured")
}
