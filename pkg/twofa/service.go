package twofa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
	"github.com/tendant/simple-idm/pkg/utils"
)

type TwoFaService struct {
	queries *twofadb.Queries
}

func NewTwoFaService(queries *twofadb.Queries) *TwoFaService {
	return &TwoFaService{
		queries: queries,
	}
}

const (
	TOTP_ISSUER = "simple-idm"
	SKEW        = 1
	PERIOD      = 300
)

const (
	twoFactorTypeEmail = "email"
	twoFactorTypeSms   = "sms"
)

func (s TwoFaService) GetTwoFactorSecretByLoginUuid(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) (string, error) {
	// Validate twoFactorType
	err := ValidateTwoFactorType(twoFactorType)
	if err != nil {
		return "", fmt.Errorf("invalid 2FA type: %w", err)
	}

	// Try to get existing 2FA record
	secret, err := s.queries.Get2FAByLoginUuid(ctx, twofadb.Get2FAByLoginUuidParams{
		LoginUuid: loginUuid,
		// FIXME: hardcoded
		TwoFactorType: utils.ToNullString(twoFactorType),
	})

	if err == nil && secret.TwoFactorSecret.String != "" {
		return secret.TwoFactorSecret.String, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		// Generate and store new secret
		newSecret := generateFakeSecret()
		_, err = s.queries.Create2FAInit(ctx, twofadb.Create2FAInitParams{
			LoginUuid:            loginUuid,
			TwoFactorSecret:      pgtype.Text{String: newSecret, Valid: true},
			TwoFactorBackupCodes: []string{},
			TwoFactorType:        utils.ToNullString(twoFactorType),
		})
		if err != nil {
			return "", fmt.Errorf("failed to create 2FA record: %w", err)
		}
		return newSecret, nil
	}
	return "", fmt.Errorf("failed to get 2FA record: %w", err)
}

func generateFakeSecret() string {
	// generate a fake secret
	return "fake-secret"
}

func (s TwoFaService) EnableTwoFactor(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) error {
	// Validate twoFactorType
	err := ValidateTwoFactorType(twoFactorType)
	if err != nil {
		return fmt.Errorf("invalid 2FA type: %w", err)
	}

	// Check if 2FA record exists and is enabled
	secret, err := s.queries.Get2FAByLoginUuid(ctx, twofadb.Get2FAByLoginUuidParams{
		LoginUuid:     loginUuid,
		TwoFactorType: utils.ToNullString(twoFactorType),
	})

	// If no record exists, return error
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no 2FA record found for user, initialize 2FA first")
	}

	// Handle other errors
	if err != nil {
		return fmt.Errorf("failed to get 2FA record: %w", err)
	}

	// Check if already enabled
	if secret.TwoFactorEnabled.Bool {
		return fmt.Errorf("2FA is already enabled for the user")
	}

	// Enable 2FA
	err = s.queries.Enable2FA(ctx, twofadb.Enable2FAParams{
		LoginUuid:     loginUuid,
		TwoFactorType: utils.ToNullString(twoFactorType),
	})
	if err != nil {
		return fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return nil
}

func (s TwoFaService) DisableTwoFactor(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) error {
	// Validate twoFactorType
	err := ValidateTwoFactorType(twoFactorType)
	if err != nil {
		return fmt.Errorf("invalid 2FA type: %w", err)
	}

	// Check if 2FA record exists and is enabled
	secret, err := s.queries.Get2FAByLoginUuid(ctx, twofadb.Get2FAByLoginUuidParams{
		LoginUuid:     loginUuid,
		TwoFactorType: utils.ToNullString(twoFactorType),
	})

	// If no record exists, return error
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no 2FA record found for user, initialize 2FA first")
	}

	// Handle other errors
	if err != nil {
		return fmt.Errorf("failed to get 2FA record: %w", err)
	}

	// Check if already disabled
	if !secret.TwoFactorEnabled.Bool {
		return fmt.Errorf("2FA is already disabled for the user")
	}

	// Disable 2FA
	err = s.queries.Disable2FA(ctx, twofadb.Disable2FAParams{
		LoginUuid:     loginUuid,
		TwoFactorType: utils.ToNullString(twoFactorType),
	})
	if err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return nil
}

func GenerateTotpSecret(loginUuid string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTP_ISSUER,
		AccountName: loginUuid,
	})
	if err != nil {
		slog.Error("Failed to generate totp secret", "loginUuid", loginUuid, "issuer", TOTP_ISSUER, "error", err)
		return "", err
	}
	totpSecret := key.Secret()
	slog.Info("Generated new totp secret", "loginUuid", loginUuid)
	return totpSecret, nil
}

func Generate2faPasscode(totpSecret string) (string, error) {
	code, err := totp.GenerateCodeCustom(totpSecret, time.Now().UTC(), totp.ValidateOpts{
		Period:    PERIOD,
		Skew:      SKEW,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		slog.Error("Failed to generate 2fa passcode", "error", err)
		return "", err
	}
	return code, nil
}

// ValidateTwoFactorType checks if the given type is a valid 2FA type
func ValidateTwoFactorType(twoFactorType string) error {
	switch twoFactorType {
	case twoFactorTypeEmail, twoFactorTypeSms:
		return nil
	default:
		return fmt.Errorf("invalid 2FA type: %s, must be one of: %s, %s",
			twoFactorType, twoFactorTypeEmail, twoFactorTypeSms)
	}
}
