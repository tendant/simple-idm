package twofa

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
