package common

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

// DeliveryOption defines a model for 2FA delivery options
type DeliveryOption struct {
	Type         string `json:"type,omitempty"`
	Value        string `json:"value,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	DisplayValue string `json:"display_value,omitempty"`
	HashedValue  string `json:"hashed_value,omitempty"`
}

// TwoFactorMethod defines a model for 2FA method
type TwoFactorMethod struct {
	Type            string           `json:"type,omitempty"`
	DeliveryOptions []DeliveryOption `json:"delivery_options,omitempty"`
}

// User defines a model for user in 2FA context
type User struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// Check2FAEnabled checks if 2FA is enabled for the given login ID and returns the 2FA methods if enabled
// Returns: (is2FAEnabled, twoFactorMethods, tempToken, error)
func Check2FAEnabled(
	ctx context.Context,
	w http.ResponseWriter,
	loginID uuid.UUID,
	idmUsers []mapper.User,
	twoFactorService twofa.TwoFactorService,
	tokenService tg.TokenService,
	tokenCookieService tg.TokenCookieService,
	associateUser bool,
) (bool, []TwoFactorMethod, *tg.TokenValue, error) {
	if twoFactorService == nil {
		return false, nil, nil, nil
	}

	enabledTwoFAs, err := twoFactorService.FindEnabledTwoFAs(ctx, loginID)
	if err != nil {
		slog.Error("Failed to find enabled 2FA", "loginUuid", loginID, "error", err)
		return false, nil, nil, fmt.Errorf("failed to find enabled 2FA: %w", err)
	}

	if len(enabledTwoFAs) == 0 {
		slog.Info("2FA is not enabled for login, skip 2FA verification", "loginUuid", loginID)
		return false, nil, nil, nil
	}

	slog.Info("2FA is enabled for login, proceed to 2FA verification", "loginUuid", loginID)

	// If email 2FA is enabled, get unique emails from users
	var twoFactorMethods []TwoFactorMethod
	for _, method := range enabledTwoFAs {
		curMethod := TwoFactorMethod{
			Type: method,
		}
		switch method {
		case twofa.TWO_FACTOR_TYPE_EMAIL:
			options := getUniqueEmailsFromUsers(idmUsers)
			curMethod.DeliveryOptions = options
		default:
			curMethod.DeliveryOptions = []DeliveryOption{}
		}
		twoFactorMethods = append(twoFactorMethods, curMethod)
	}

	extraClaims := map[string]interface{}{
		"login_id": loginID.String(),
	}
	// Add user options to extra claims if provided
	if associateUser {
		slog.Info("associate users", "login_id", loginID)
		extraClaims["associate_users"] = true
	}

	// Updated to use the new TokenService interface
	tempTokenMap, err := tokenService.GenerateTempToken(idmUsers[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return false, nil, nil, fmt.Errorf("failed to generate temp token: %w", err)
	}

	tempToken := tempTokenMap[tg.TEMP_TOKEN_NAME]

	// Only set cookie if a writer is provided (web flow)
	if w != nil {
		err = tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return false, nil, nil, fmt.Errorf("failed to set temp token cookie: %w", err)
		}
	}

	return true, twoFactorMethods, &tempToken, nil
}

// GetUniqueEmailsFromUsers extracts unique emails from a list of users
func getUniqueEmailsFromUsers(users []mapper.User) []DeliveryOption {
	emailMap := make(map[string]bool)
	var deliveryOptions []DeliveryOption

	for _, user := range users {
		// Get email from UserInfo
		email := user.UserInfo.Email
		if emailMap[email] || email == "" {
			continue
		}

		deliveryOptions = append(deliveryOptions, DeliveryOption{
			Type:         "email",
			Value:        email,
			UserID:       user.UserId,
			DisplayValue: utils.MaskEmail(email),
			HashedValue:  utils.HashEmail(email),
		})
		emailMap[email] = true
	}

	return deliveryOptions
}

func RememberDevice(r *http.Request, loginID uuid.UUID, deviceService device.DeviceService) (bool, error) {
	// get fingerprint from request
	fingerprint := device.ExtractFingerprintDataFromRequest(r)
	fingerprintStr := device.GenerateFingerprint(fingerprint)

	slog.Info("Remembering device", "fingerprint", fingerprintStr, "loginID", loginID)

	// check if device is already linked to login and not expired
	loginDevice, err := deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), fingerprintStr, loginID)
	if err == nil && loginDevice != nil && !loginDevice.IsExpired() {
		// Device is recognized and not expired, skip 2FA
		slog.Info("Device recognized", "fingerprint", fingerprintStr, "loginID", loginID)
		return true, nil
	}

	slog.Info("Device not recognized or expired", "fingerprint", fingerprintStr, "loginID", loginID)
	// register new device
	_, err = deviceService.GetDeviceByFingerprint(r.Context(), fingerprintStr)
	if err != nil {
		slog.Info("registering device", "fingerprint", fingerprintStr)
		_, err = deviceService.RegisterDevice(r.Context(), fingerprintStr, r.UserAgent())
		if err != nil {
			slog.Error("Failed to register device", "err", err)
			return false, err
		}
	}
	slog.Info("linking device to login", "fingerprint", fingerprintStr, "loginID", loginID)
	err = deviceService.LinkDeviceToLogin(r.Context(), loginID, fingerprintStr)
	if err != nil {
		slog.Error("Failed to link device to login", "err", err)
		return false, err
	}
	return true, nil
}
