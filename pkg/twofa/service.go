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
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/notice"
	"github.com/tendant/simple-idm/pkg/notification"
	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
	"github.com/tendant/simple-idm/pkg/utils"
)

type TwoFactorService interface {
	GetTwoFactorSecretByLoginId(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) (string, error)
	SendTwoFaNotification(ctx context.Context, loginId, userId uuid.UUID, twoFactorType, hashedDeliveryOption string) error
	FindTwoFAsByLoginId(ctx context.Context, loginId uuid.UUID) ([]TwoFA, error)
	FindEnabledTwoFAs(ctx context.Context, loginId uuid.UUID) ([]string, error)
	EnableTwoFactor(ctx context.Context, loginId uuid.UUID, twoFactorType string) error
	DisableTwoFactor(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) error
	DeleteTwoFactor(ctx context.Context, params DeleteTwoFactorParams) error
	SendTwofaPasscodeEmail(ctx context.Context, email, passcode string, userId uuid.UUID) error
	Validate2faPasscode(ctx context.Context, loginId uuid.UUID, twoFactorType, passcode string) (bool, error)
}

type TwoFaService struct {
	queries             *twofadb.Queries
	notificationManager *notification.NotificationManager
	userMapper          mapper.UserMapper
}

func NewTwoFaService(queries *twofadb.Queries, notificationManager *notification.NotificationManager, userMapper mapper.UserMapper) *TwoFaService {
	return &TwoFaService{
		queries:             queries,
		notificationManager: notificationManager,
		userMapper:          userMapper,
	}
}

type (
	TwoFA struct {
		LoginId          uuid.UUID `json:"login_id"`
		TwoFactorId      uuid.UUID `json:"two_factor_id"`
		TwoFactorType    string    `json:"two_factor_type"`
		TwoFactorEnabled bool      `json:"two_factor_enabled"`
		CreatedAt        time.Time `json:"created_at"`
		UpdatedAt        time.Time `json:"updated_at"`
	}

	DeleteTwoFactorParams struct {
		LoginId       uuid.UUID `json:"login_id"`
		TwoFactorType string    `json:"two_factor_type"`
		TwoFactorId   uuid.UUID `json:"two_factor_id"`
	}
)

const (
	TOTP_ISSUER = "simple-idm"
	SKEW        = 1
	PERIOD      = 300
)

const (
	TWO_FACTOR_TYPE_EMAIL = "email"
	TWO_FACTOR_TYPE_SMS   = "sms"
)

func (s TwoFaService) GetTwoFactorSecretByLoginId(ctx context.Context, loginUuid uuid.UUID, twoFactorType string) (string, error) {
	// Validate twoFactorType
	err := ValidateTwoFactorType(twoFactorType)
	if err != nil {
		return "", fmt.Errorf("invalid 2FA type: %w", err)
	}

	// Try to get existing 2FA record
	secret, err := s.queries.Get2FAByLoginId(ctx, twofadb.Get2FAByLoginIdParams{
		LoginID: loginUuid,
		// FIXME: hardcoded
		TwoFactorType: utils.ToNullString(twoFactorType),
	})

	if err == nil && secret.TwoFactorSecret.String != "" {
		return secret.TwoFactorSecret.String, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("2FA record does not exist for login ID: %s", loginUuid)
	}
	return "", fmt.Errorf("failed to get 2FA record: %w", err)
}

// InitTwoFa generate a two factor passcode and send a notification email
func (s TwoFaService) SendTwoFaNotification(ctx context.Context, loginId, userId uuid.UUID, twoFactorType, hashedDeliveryOption string) error {
	// get or create the 2fa secret for the login
	secret, err := s.GetTwoFactorSecretByLoginId(ctx, loginId, twoFactorType)
	if err != nil {
		return err
	}

	// generate and send the passcode
	passcode, err := Generate2faPasscode(secret)
	if err != nil {
		return fmt.Errorf("failed to generate and send 2FA passcode: %w", err)
	}

	// If delivery_option is provided and the type is email, use it instead of the email parameter
	emailToUse := hashedDeliveryOption
	if twoFactorType == TWO_FACTOR_TYPE_EMAIL && hashedDeliveryOption != "" {
		// get the plaintext email by hash
		emailToUse, err = s.GetPlaintextEmailByHash(ctx, loginId, hashedDeliveryOption)
		if err != nil {
			return fmt.Errorf("failed to get user plaintext email: %w", err)
		}
	}

	// send the passcode by email
	err = s.SendTwofaPasscodeEmail(ctx, emailToUse, passcode, userId)
	if err != nil {
		return fmt.Errorf("failed to send 2FA passcode: %w", err)
	}

	return nil
}

func (s TwoFaService) FindEnabledTwoFAs(ctx context.Context, loginId uuid.UUID) ([]string, error) {
	enabled2fas, err := s.queries.FindEnabledTwoFAs(ctx, loginId)
	if err != nil {
		slog.Error("Failed to find enabled 2FA", "loginUuid", loginId, "error", err)
		return nil, fmt.Errorf("failed to find enabled 2FA: %w", err)
	}

	res := []string{}
	for _, e := range enabled2fas {
		res = append(res, e.TwoFactorType.String)
	}
	return res, nil
}

func (s TwoFaService) FindTwoFAsByLoginId(ctx context.Context, loginId uuid.UUID) ([]TwoFA, error) {
	var res []TwoFA
	twofas, err := s.queries.FindTwoFAsByLoginId(ctx, loginId)
	if err != nil {
		slog.Error("Failed to find 2FA by login ID", "loginUuid", loginId, "error", err)
		return nil, fmt.Errorf("failed to find 2FA by login ID: %w", err)
	}

	for _, t := range twofas {
		res = append(res, TwoFA{
			TwoFactorId:      t.ID,
			TwoFactorType:    t.TwoFactorType.String,
			TwoFactorEnabled: t.TwoFactorEnabled.Bool,
			CreatedAt:        t.CreatedAt,
		})
	}

	return res, nil
}

// CreateTwoFactor create a new 2FA record with enabled as true
func (s TwoFaService) CreateTwoFactor(ctx context.Context, loginId uuid.UUID, twoFactorType string) error {
	// Validate twoFactorType
	err := ValidateTwoFactorType(twoFactorType)
	if err != nil {
		return fmt.Errorf("invalid 2FA type: %w", err)
	}

	// Check if 2FA record exists and is enabled
	_, err = s.queries.Get2FAByLoginId(ctx, twofadb.Get2FAByLoginIdParams{
		LoginID:       loginId,
		TwoFactorType: utils.ToNullString(twoFactorType),
	})

	// If no record exists, process create 2fa init
	if errors.Is(err, pgx.ErrNoRows) {
		// Generate and store new secret
		newSecret, err := GenerateTotpSecret(loginId.String())
		if err != nil {
			return fmt.Errorf("failed to generate 2fa secret: %w", err)
		}

		// !! create 2fa record and set enabled to false: hardcoded in query
		_, err = s.queries.Create2FAInit(ctx, twofadb.Create2FAInitParams{
			LoginID:              loginId,
			TwoFactorSecret:      pgtype.Text{String: newSecret, Valid: true},
			TwoFactorBackupCodes: []string{},
			TwoFactorType:        utils.ToNullString(twoFactorType),
		})
		if err != nil {
			return fmt.Errorf("failed to create 2FA record: %w", err)
		}
		return nil
	}

	// Handle other errors
	if err != nil {
		return fmt.Errorf("failed to get 2FA record: %w", err)
	}

	return fmt.Errorf("2FA is already exists for the user with type: %s", twoFactorType)
}

func (s TwoFaService) EnableTwoFactor(ctx context.Context, loginId uuid.UUID, twoFactorType string) error {
	// Validate twoFactorType
	err := ValidateTwoFactorType(twoFactorType)
	if err != nil {
		return fmt.Errorf("invalid 2FA type: %w", err)
	}

	// Check if 2FA record exists and is enabled
	secret, err := s.queries.Get2FAByLoginId(ctx, twofadb.Get2FAByLoginIdParams{
		LoginID: loginId,
		// FIXME: hardcoded
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
		LoginID:       loginId,
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
	secret, err := s.queries.Get2FAByLoginId(ctx, twofadb.Get2FAByLoginIdParams{
		LoginID: loginUuid,
		// FIXME: hardcoded
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
		LoginID:       loginUuid,
		TwoFactorType: utils.ToNullString(twoFactorType),
	})
	if err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return nil
}

func (s TwoFaService) SendTwofaPasscodeEmail(ctx context.Context, email, passcode string, userId uuid.UUID) error {
	// TODO: use userId to send email to users
	data := map[string]string{
		"TwofaPasscode": passcode,
		"UserId":        userId.String(),
	}
	return s.notificationManager.Send(notice.TwofaCodeNotice, notification.NotificationData{
		To:   email,
		Data: data,
	})
}

func (s TwoFaService) DeleteTwoFactor(ctx context.Context, params DeleteTwoFactorParams) error {
	// TODO: add logic to check if 2FA is enabled before deleting

	_, err := s.queries.Get2FAById(ctx, twofadb.Get2FAByIdParams{
		ID:            params.TwoFactorId,
		LoginID:       params.LoginId,
		TwoFactorType: utils.ToNullString(params.TwoFactorType),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("2FA not found")
		}
		return fmt.Errorf("failed to get 2FA: %w", err)
	}

	err = s.queries.Delete2FA(ctx, twofadb.Delete2FAParams{
		ID:            params.TwoFactorId,
		LoginID:       params.LoginId,
		TwoFactorType: utils.ToNullString(params.TwoFactorType),
	})
	if err != nil {
		return fmt.Errorf("failed to delete 2FA: %w", err)
	}

	return nil
}

func (s TwoFaService) Validate2faPasscode(ctx context.Context, loginId uuid.UUID, twoFactorType, passcode string) (bool, error) {
	secret, err := s.queries.Get2FAByLoginId(ctx, twofadb.Get2FAByLoginIdParams{
		LoginID: loginId,
		// FIXME: hardcoded
		TwoFactorType: utils.ToNullString(twoFactorType),
	})

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("No 2FA record found for user", "loginUuid", loginId, "twoFactorType", twoFactorType)
			return false, fmt.Errorf("no 2FA record found for user")
		}
		return false, fmt.Errorf("failed to get 2FA record: %w", err)
	}

	res, err := ValidateTotpPasscode(secret.TwoFactorSecret.String, passcode)
	if err != nil {
		return false, fmt.Errorf("failed to validate 2FA passcode: %w", err)
	}

	return res, nil
}

func (s TwoFaService) GetPlaintextEmailByHash(ctx context.Context, loginID uuid.UUID, hashedEmail string) (string, error) {
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		slog.Error("Failed to get users by login ID", "loginID", loginID, "error", err)
		return "", fmt.Errorf("error getting users: %w", err)
	}

	for _, user := range users {
		if utils.HashEmail(user.Email) == hashedEmail {
			return user.Email, nil
		}
	}

	return "", fmt.Errorf("email not found")
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

func ValidateTotpPasscode(totpSecret, passcode string) (bool, error) {
	valid, err := totp.ValidateCustom(passcode, totpSecret, time.Now().UTC(), totp.ValidateOpts{
		Period:    PERIOD,
		Skew:      SKEW,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		slog.Error("Failed to validate totp passcode", "error", err)
		return false, err
	}
	return valid, nil
}

// ValidateTwoFactorType checks if the given type is a valid 2FA type
func ValidateTwoFactorType(twoFactorType string) error {
	switch twoFactorType {
	case TWO_FACTOR_TYPE_EMAIL, TWO_FACTOR_TYPE_SMS:
		return nil
	default:
		return fmt.Errorf("invalid 2FA type: %s, must be one of: %s, %s",
			twoFactorType, TWO_FACTOR_TYPE_EMAIL, TWO_FACTOR_TYPE_SMS)
	}
}
