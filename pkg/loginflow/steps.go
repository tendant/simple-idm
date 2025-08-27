package loginflow

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/utils"
)

// CredentialAuthenticationStep handles user credential validation
type CredentialAuthenticationStep struct {
	loginType string // "username", "email", or "magic_link"
}

func NewCredentialAuthenticationStep(loginType string) *CredentialAuthenticationStep {
	return &CredentialAuthenticationStep{loginType: loginType}
}

func (s *CredentialAuthenticationStep) Name() string {
	return "credential_authentication"
}

func (s *CredentialAuthenticationStep) Order() int {
	return OrderCredentialAuthentication
}

func (s *CredentialAuthenticationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always execute credential authentication
}

func (s *CredentialAuthenticationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	var loginResult login.LoginResult
	var err error

	switch s.loginType {
	case "username":
		loginResult, err = flowContext.Services.LoginService.Login(ctx, flowContext.Request.Username, flowContext.Request.Password)
	case "email":
		loginResult, err = flowContext.Services.LoginService.LoginByEmail(ctx, flowContext.Request.Username, flowContext.Request.Password)
	case "magic_link":
		// For magic link, the "password" field contains the token
		loginResult, err = flowContext.Services.LoginService.ValidateMagicLinkToken(ctx, flowContext.Request.Password)
	default:
		return &StepResult{
			Error: &Error{
				Type:    "invalid_login_type",
				Message: "Invalid login type specified",
			},
		}, nil
	}

	if err != nil {
		slog.Error("Login failed", "err", err, "type", s.loginType)

		// Record the login attempt
		flowContext.Services.LoginService.RecordLoginAttempt(ctx, loginResult.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprint, false, loginResult.FailureReason)

		// Handle specific error types
		if login.IsAccountLockedError(err) {
			lockoutDuration := flowContext.Services.LoginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			return &StepResult{
				Error: &Error{
					Type:    "account_locked",
					Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				},
			}, nil
		}

		if strings.Contains(err.Error(), "password has expired") {
			return &StepResult{
				Error: &Error{
					Type:    "password_expired",
					Message: "Your password has expired and must be changed before you can log in.",
				},
			}, nil
		}

		errorMessage := "Username/Password is wrong"
		if s.loginType == "email" {
			errorMessage = "Email/Password is wrong"
		} else if s.loginType == "magic_link" {
			errorMessage = "Invalid or expired token"
		}

		return &StepResult{
			Error: &Error{
				Type:    "invalid_credentials",
				Message: errorMessage,
			},
		}, nil
	}

	// Store login result in flow context
	flowContext.Result.LoginID = loginResult.LoginID
	flowContext.Result.Users = loginResult.Users

	return &StepResult{
		Continue: true,
		Data: map[string]interface{}{
			"login_result": loginResult,
		},
	}, nil
}

// UserValidationStep validates that users exist after authentication
type UserValidationStep struct{}

func NewUserValidationStep() *UserValidationStep {
	return &UserValidationStep{}
}

func (s *UserValidationStep) Name() string {
	return "user_validation"
}

func (s *UserValidationStep) Order() int {
	return OrderUserValidation
}

func (s *UserValidationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always validate users
}

func (s *UserValidationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	if len(flowContext.Result.Users) == 0 {
		slog.Error("No user found after login")
		flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.Result.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprint, false, login.FAILURE_REASON_NO_USER_FOUND)

		return &StepResult{
			Error: &Error{
				Type:    "no_user_found",
				Message: "Account not active",
			},
		}, nil
	}

	return &StepResult{Continue: true}, nil
}

// LoginIDParsingStep parses and validates the login ID
type LoginIDParsingStep struct{}

func NewLoginIDParsingStep() *LoginIDParsingStep {
	return &LoginIDParsingStep{}
}

func (s *LoginIDParsingStep) Name() string {
	return "login_id_parsing"
}

func (s *LoginIDParsingStep) Order() int {
	return OrderLoginIDParsing
}

func (s *LoginIDParsingStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always parse login ID
}

func (s *LoginIDParsingStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	loginID, err := uuid.Parse(flowContext.Result.Users[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", flowContext.Result.Users[0].LoginID, "error", err)
		flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.Result.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		return &StepResult{
			Error: &Error{
				Type:    "internal_error",
				Message: "Invalid login ID",
			},
		}, nil
	}

	// Update the login ID in flow context
	flowContext.LoginID = loginID
	flowContext.Result.LoginID = loginID

	return &StepResult{Continue: true}, nil
}

// DeviceRecognitionStep checks if the device is recognized
type DeviceRecognitionStep struct{}

func NewDeviceRecognitionStep() *DeviceRecognitionStep {
	return &DeviceRecognitionStep{}
}

func (s *DeviceRecognitionStep) Name() string {
	return "device_recognition"
}

func (s *DeviceRecognitionStep) Order() int {
	return OrderDeviceRecognition
}

func (s *DeviceRecognitionStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return flowContext.Request.DeviceFingerprint == "" // Skip if no fingerprint
}

func (s *DeviceRecognitionStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Check if this device is linked to the login
	loginDevice, err := flowContext.Services.DeviceService.FindLoginDeviceByFingerprintAndLoginID(ctx, flowContext.Request.DeviceFingerprint, flowContext.LoginID)
	if err != nil {
		// Device not found or error occurred
		flowContext.DeviceRecognized = false
		flowContext.Result.DeviceRecognized = false
		return &StepResult{Continue: true}, nil
	}

	// Check if device has IsExpired method
	if loginDevice.IsExpired() {
		// Device link has expired
		flowContext.DeviceRecognized = false
		flowContext.Result.DeviceRecognized = false
		return &StepResult{Continue: true}, nil
	}

	// Device is recognized and not expired
	slog.Info("Device recognized, skipping 2FA", "fingerprint", flowContext.Request.DeviceFingerprint, "loginID", flowContext.LoginID)
	flowContext.DeviceRecognized = true
	flowContext.Result.DeviceRecognized = true

	return &StepResult{Continue: true}, nil
}

// TwoFARequirementStep checks if 2FA is required
type TwoFARequirementStep struct{}

func NewTwoFARequirementStep() *TwoFARequirementStep {
	return &TwoFARequirementStep{}
}

func (s *TwoFARequirementStep) Name() string {
	return "two_fa_requirement"
}

func (s *TwoFARequirementStep) Order() int {
	return OrderTwoFARequirement
}

func (s *TwoFARequirementStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return flowContext.DeviceRecognized // Skip 2FA if device is recognized
}

func (s *TwoFARequirementStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	enabledTwoFAs, err := flowContext.Services.TwoFactorService.FindEnabledTwoFAs(ctx, flowContext.LoginID)
	if err != nil {
		slog.Error("Failed to find enabled 2FA", "loginUuid", flowContext.LoginID, "error", err)
		return &StepResult{
			Error: &Error{
				Type:    "internal_error",
				Message: "Failed to find enabled 2FA",
			},
		}, nil
	}

	if len(enabledTwoFAs) == 0 {
		slog.Info("2FA is not enabled for login, skip 2FA verification", "loginUuid", flowContext.LoginID)
		return &StepResult{Continue: true}, nil
	}

	slog.Info("2FA is enabled for login, proceed to 2FA verification", "loginUuid", flowContext.LoginID)

	// Build 2FA methods with delivery options
	var twoFactorMethods []TwoFactorMethod
	for _, method := range enabledTwoFAs {
		curMethod := TwoFactorMethod{
			Type: method,
		}
		switch method {
		case "email": // Assuming twofa.TWO_FACTOR_TYPE_EMAIL is "email"
			options := getUniqueEmailsFromUsersForSteps(flowContext.Result.Users)
			curMethod.DeliveryOptions = options
		case "sms": // Assuming twofa.TWO_FACTOR_TYPE_SMS is "sms"
			options := getUniquePhonesFromUsersForSteps(flowContext.Result.Users)
			curMethod.DeliveryOptions = options
		default:
			curMethod.DeliveryOptions = []DeliveryOption{}
		}
		twoFactorMethods = append(twoFactorMethods, curMethod)
	}

	extraClaims := map[string]interface{}{
		"login_id": flowContext.LoginID.String(),
	}

	// Generate temp token
	tempTokenMap, err := flowContext.Services.TokenService.GenerateTempToken(flowContext.Result.Users[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return &StepResult{
			Error: &Error{
				Type:    "internal_error",
				Message: "Failed to generate temp token",
			},
		}, nil
	}

	// Set 2FA requirement in result
	flowContext.Result.RequiresTwoFA = true
	flowContext.Result.TwoFactorMethods = twoFactorMethods
	flowContext.Result.Tokens = tempTokenMap

	return &StepResult{
		EarlyReturn: true, // Return early for 2FA
	}, nil
}

// MultipleUsersStep handles multiple user selection
type MultipleUsersStep struct{}

func NewMultipleUsersStep() *MultipleUsersStep {
	return &MultipleUsersStep{}
}

func (s *MultipleUsersStep) Name() string {
	return "multiple_users"
}

func (s *MultipleUsersStep) Order() int {
	return OrderMultipleUsers
}

func (s *MultipleUsersStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return len(flowContext.Result.Users) <= 1 // Skip if single user or no users
}

func (s *MultipleUsersStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Create temp token with the custom claims for user selection
	extraClaims := map[string]interface{}{
		"login_id":     flowContext.LoginID.String(),
		"2fa_verified": true, // This step will only be called if 2FA is not enabled or 2FA validation is passed
	}

	tempTokenMap, err := flowContext.Services.TokenService.GenerateTempToken(flowContext.Result.Users[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return &StepResult{
			Error: &Error{
				Type:    "internal_error",
				Message: "Failed to generate temp token",
			},
		}, nil
	}

	flowContext.Result.RequiresUserSelection = true
	flowContext.Result.Tokens = tempTokenMap

	return &StepResult{
		EarlyReturn: true, // Return early for user selection
	}, nil
}

// TokenGenerationStep generates JWT tokens for successful login
type TokenGenerationStep struct {
	tokenType string // "web" or "mobile"
}

func NewTokenGenerationStep(tokenType string) *TokenGenerationStep {
	return &TokenGenerationStep{tokenType: tokenType}
}

func (s *TokenGenerationStep) Name() string {
	return "token_generation"
}

func (s *TokenGenerationStep) Order() int {
	return OrderTokenGeneration
}

func (s *TokenGenerationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always generate tokens for successful login
}

func (s *TokenGenerationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Create JWT tokens using the appropriate service method
	rootModifications, extraClaims := flowContext.Services.LoginService.ToTokenClaims(flowContext.Result.Users[0])

	var tokens map[string]tg.TokenValue
	var err error

	switch s.tokenType {
	case "mobile":
		tokens, err = flowContext.Services.TokenService.GenerateMobileTokens(flowContext.Result.Users[0].UserId, rootModifications, extraClaims)
	default: // "web" or any other type defaults to regular tokens
		tokens, err = flowContext.Services.TokenService.GenerateTokens(flowContext.Result.Users[0].UserId, rootModifications, extraClaims)
	}

	if err != nil {
		slog.Error("Failed to generate tokens", "err", err, "type", s.tokenType)
		return &StepResult{
			Error: &Error{
				Type:    "internal_error",
				Message: "Failed to generate tokens",
			},
		}, nil
	}

	flowContext.Result.Tokens = tokens

	return &StepResult{Continue: true}, nil
}

// SuccessRecordingStep records successful login and updates device
type SuccessRecordingStep struct{}

func NewSuccessRecordingStep() *SuccessRecordingStep {
	return &SuccessRecordingStep{}
}

func (s *SuccessRecordingStep) Name() string {
	return "success_recording"
}

func (s *SuccessRecordingStep) Order() int {
	return OrderSuccessRecording
}

func (s *SuccessRecordingStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always record successful login
}

func (s *SuccessRecordingStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Record successful login attempt
	flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprint, true, "")

	// Update device last login time
	if flowContext.Request.DeviceFingerprint != "" {
		_, err := flowContext.Services.DeviceService.UpdateDeviceLastLogin(ctx, flowContext.Request.DeviceFingerprint)
		if err != nil {
			slog.Error("Failed to update device last login time", "error", err, "fingerprint", flowContext.Request.DeviceFingerprint)
			// Don't fail the login if we can't update the last login time
		}
	}

	// Mark login as successful
	flowContext.Result.Success = true

	return &StepResult{Continue: true}, nil
}

// Helper functions for 2FA delivery options

// getUniqueEmailsFromUsersForSteps extracts unique emails from a list of users for steps
func getUniqueEmailsFromUsersForSteps(users []mapper.User) []DeliveryOption {
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

// getUniquePhonesFromUsersForSteps extracts unique phones from a list of users for steps
func getUniquePhonesFromUsersForSteps(users []mapper.User) []DeliveryOption {
	phoneMap := make(map[string]bool)
	var deliveryOptions []DeliveryOption

	for _, user := range users {
		// Get phone from UserInfo
		phone := user.UserInfo.PhoneNumber
		if phoneMap[phone] || phone == "" {
			continue
		}

		deliveryOptions = append(deliveryOptions, DeliveryOption{
			Type:         "sms",
			Value:        phone,
			UserID:       user.UserId,
			DisplayValue: utils.MaskPhone(phone),
			HashedValue:  utils.HashPhone(phone),
		})
		phoneMap[phone] = true
	}

	return deliveryOptions
}
