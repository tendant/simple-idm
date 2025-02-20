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

func (s TwoFaService) GetTwoFactorSecretByLoginUuid(ctx context.Context, loginUuid uuid.UUID) (string, error) {
	// Try to get existing 2FA record
	secret, err := s.queries.Get2FAByLoginUuid(ctx, twofadb.Get2FAByLoginUuidParams{
		LoginUuid: loginUuid,
		// FIXME: hardcoded
		TwoFactorType: utils.ToNullString(twoFactorTypeEmail),
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
