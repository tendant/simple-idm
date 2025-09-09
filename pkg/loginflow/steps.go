package loginflow

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		loginResult, err = flowContext.Services.LoginService.ValidateMagicLinkToken(ctx, flowContext.Request.MagicLinkToken)
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
		if loginResult.LoginID != uuid.Nil {
			flowContext.Services.LoginService.RecordLoginAttempt(ctx, loginResult.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprintStr, false, loginResult.FailureReason)
		}

		// Handle specific error types
		if login.IsAccountLockedError(err) {
			lockoutDuration := flowContext.Services.LoginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			return &StepResult{
				Error: &Error{
					Type:    ErrorTypeAccountLocked,
					Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				},
			}, nil
		}

		if strings.Contains(err.Error(), "password has expired") {
			return &StepResult{
				Error: &Error{
					Type:    ErrorTypePasswordExpired,
					Message: "Your password has expired, please reset your password through the forgot password link.",
				},
			}, nil
		}

		errorMessage := "Username/Password is wrong"
		switch {
		case s.loginType == "email":
			errorMessage = "Email/Password is wrong"
		case s.loginType == "magic_link":
			errorMessage = "Invalid or expired token"
		}

		return &StepResult{
			Error: &Error{
				Type:    ErrorTypeInvalidCredentials,
				Message: errorMessage,
			},
		}, nil
	}

	extraClaims := map[string]interface{}{
		"login_id": flowContext.LoginID.String(),
	}
	// Store login result in flow context
	flowContext.LoginID = loginResult.LoginID
	flowContext.Result.Users = loginResult.Users

	// Generate temp token
	tempTokenMap, err := flowContext.Services.TokenService.GenerateTempToken(flowContext.Result.Users[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return &StepResult{
			Error: &Error{
				Type:    ErrorTypeInternalError,
				Message: "Failed to generate temp token",
			},
		}, nil
	}

	flowContext.Result.Tokens = tempTokenMap

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
		flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.Result.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)

		return &StepResult{
			Error: &Error{
				Type:    ErrorTypeNoUserFound,
				Message: "Account not active",
			},
		}, nil
	}

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
	return flowContext.Request.DeviceFingerprintStr == "" // Skip if no fingerprint
}

func (s *DeviceRecognitionStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Check if this device is linked to the login
	loginDevice, err := flowContext.Services.DeviceService.FindLoginDeviceByFingerprintAndLoginID(ctx, flowContext.Request.DeviceFingerprintStr, flowContext.LoginID)
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
		slog.Info("Generating web tokens")
		tokens, err = flowContext.Services.TokenService.GenerateTokens(flowContext.Result.Users[0].UserId, rootModifications, extraClaims)
		slog.Info("Web tokens generated successfully")
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
	flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprintStr, true, "")

	// Update device last login time
	if flowContext.Request.DeviceFingerprintStr != "" {
		_, err := flowContext.Services.DeviceService.UpdateDeviceLastLogin(ctx, flowContext.Request.DeviceFingerprintStr)
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

// TempTokenValidationStep validates temp tokens for resumption flows
type TempTokenValidationStep struct{}

func NewTempTokenValidationStep() *TempTokenValidationStep {
	return &TempTokenValidationStep{}
}

func (s *TempTokenValidationStep) Name() string {
	return "temp_token_validation"
}

func (s *TempTokenValidationStep) Order() int {
	return 50 // Execute before credential authentication
}

func (s *TempTokenValidationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return !flowContext.Request.IsResumption // Skip for initial flows
}

func (s *TempTokenValidationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Parse and validate temp token
	token, err := flowContext.Services.TokenService.ParseToken(flowContext.Request.TempToken)
	if err != nil {
		return &StepResult{
			Error: &Error{Type: "invalid_token", Message: "Invalid temp token"},
		}, nil
	}

	// Extract state from token claims using jwt.MapClaims
	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
		// Convert jwt.MapClaims to map[string]interface{} for storage
		claimsMap := make(map[string]interface{})
		for key, value := range mapClaims {
			if key == "extra_claims" {
				// Handle extra_claims by flattening them into the main map
				if extraClaims, ok := value.(map[string]interface{}); ok {
					for extraKey, extraValue := range extraClaims {
						claimsMap[extraKey] = extraValue
					}
				}
			} else {
				claimsMap[key] = value
			}
		}
		flowContext.TempTokenClaims = claimsMap
		flowContext.IsResumption = true

		// Extract login_id from token claims
		if loginIDStr, exists := claimsMap["login_id"].(string); exists {
			if loginID, err := uuid.Parse(loginIDStr); err == nil {
				flowContext.LoginID = loginID
				flowContext.Result.LoginID = loginID
			}
		}

		// Reconstruct users from token or fetch from DB if needed
		if flowContext.LoginID != uuid.Nil {
			users, err := flowContext.Services.UserMapper.FindUsersByLoginID(ctx, flowContext.LoginID)
			if err == nil {
				flowContext.Result.Users = users
				flowContext.Users = users
			}
		}
	}

	return &StepResult{Continue: true}, nil
}

// TwoFAValidationStep validates 2FA codes during resumption
type TwoFAValidationStep struct{}

func NewTwoFAValidationStep() *TwoFAValidationStep {
	return &TwoFAValidationStep{}
}

func (s *TwoFAValidationStep) Name() string {
	return "two_fa_validation"
}

func (s *TwoFAValidationStep) Order() int {
	return 550 // Execute after TwoFARequirement but before MultipleUsers
}

func (s *TwoFAValidationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	// Skip if not resumption or no 2FA code provided
	return !flowContext.Request.IsResumption || flowContext.Request.TwoFACode == ""
}

func (s *TwoFAValidationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Validate 2FA code
	valid, err := flowContext.Services.TwoFactorService.Validate2faPasscode(
		ctx,
		flowContext.LoginID,
		flowContext.Request.TwoFAType,
		flowContext.Request.TwoFACode,
	)

	if err != nil {
		flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprintStr, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		return &StepResult{
			Error: &Error{Type: "internal_error", Message: "failed to validate 2fa: " + err.Error()},
		}, nil
	}

	if !valid {
		// Record failed 2FA validation attempt
		flowContext.Services.LoginService.RecordLoginAttempt(ctx, flowContext.LoginID, flowContext.Request.IPAddress, flowContext.Request.UserAgent, flowContext.Request.DeviceFingerprintStr, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)

		// Check if account should be locked
		locked, _, err := flowContext.Services.LoginService.IncrementFailedAttemptsAndCheckLock(ctx, flowContext.LoginID)
		if err != nil {
			slog.Error("Failed to increment failed attempts", "err", err)
		}
		if locked {
			lockoutDuration := flowContext.Services.LoginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			return &StepResult{
				Error: &Error{
					Type:    "account_locked",
					Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
				},
			}, nil
		}
		return &StepResult{
			Error: &Error{Type: "invalid_2fa_code", Message: "Invalid 2FA code"},
		}, nil
	}

	if flowContext.Request.RememberDevice {
		// Remember the device for future logins
		flowContext.Services.DeviceService.RememberDevice(ctx, flowContext.Request.DeviceFingerprint, flowContext.LoginID)
	}

	// Mark 2FA as verified in context
	flowContext.StepData["2fa_verified"] = true

	return &StepResult{Continue: true}, nil
}

// UserSwitchValidationStep validates user switching requests
type UserSwitchValidationStep struct{}

func NewUserSwitchValidationStep() *UserSwitchValidationStep {
	return &UserSwitchValidationStep{}
}

func (s *UserSwitchValidationStep) Name() string {
	return "user_switch_validation"
}

func (s *UserSwitchValidationStep) Order() int {
	return 560 // Execute after TwoFAValidation
}

func (s *UserSwitchValidationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	// Skip if not resumption or no target user specified
	return !flowContext.Request.IsResumption || flowContext.Request.Username == ""
}

func (s *UserSwitchValidationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {

	// Get all users for the current login
	users, err := flowContext.Services.LoginService.GetUsersByLoginId(ctx, flowContext.LoginID)
	if err != nil {
		slog.Error("Failed to get users", "err", err)
		return &StepResult{
			Error: &Error{Type: "internal_error", Message: "Failed to get users"},
		}, nil
	}

	slog.Info("users available to switch", "users", users, "loginid", flowContext.LoginID)

	// Check if the requested user is in the list (Username contains target user ID for user switch)
	targetUserID := flowContext.Request.Username
	var targetUser mapper.User
	found := false
	for _, user := range users {
		if user.UserId == targetUserID {
			targetUser = user
			found = true
			break
		}
	}

	if !found {
		return &StepResult{
			Error: &Error{Type: "forbidden", Message: "Not authorized to switch to this user"},
		}, nil
	}

	// Set the target user as the single user in the result
	flowContext.Result.Users = []mapper.User{targetUser}

	return &StepResult{Continue: true}, nil
}

// UserLookupStep handles user lookup operations
type UserLookupStep struct{}

func NewUserLookupStep() *UserLookupStep {
	return &UserLookupStep{}
}

func (s *UserLookupStep) Name() string {
	return "user_lookup"
}

func (s *UserLookupStep) Order() int {
	return 570 // Execute after UserSwitchValidation
}

func (s *UserLookupStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always execute user lookup
}

func (s *UserLookupStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Validate 2FA if using temp token (check from temp token claims)
	if twofaVerified, exists := flowContext.TempTokenClaims["2fa_verified"].(bool); !exists || !twofaVerified {
		return &StepResult{
			Error: &Error{Type: "unauthorized", Message: "2FA not verified"},
		}, nil
	}

	// Get all users for the current login
	users, err := flowContext.Services.LoginService.GetUsersByLoginId(ctx, flowContext.LoginID)
	if err != nil {
		slog.Error("Failed to get users", "err", err)
		return &StepResult{
			Error: &Error{Type: "internal_error", Message: "Failed to get users"},
		}, nil
	}

	// Set users in the result
	flowContext.Result.Users = users
	flowContext.Result.Success = true

	return &StepResult{Continue: true}, nil
}

// TwoFASendStep handles sending 2FA notifications
type TwoFASendStep struct{}

func NewTwoFASendStep() *TwoFASendStep {
	return &TwoFASendStep{}
}

func (s *TwoFASendStep) Name() string {
	return "two_fa_send"
}

func (s *TwoFASendStep) Order() int {
	return 580 // Execute after UserLookup
}

func (s *TwoFASendStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	return false // Always execute 2FA send
}

func (s *TwoFASendStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Extract user ID and delivery option from request
	userID, err := uuid.Parse(flowContext.Request.Username) // Username contains user ID for 2FA send
	if err != nil {
		return &StepResult{
			Error: &Error{Type: "invalid_request", Message: "Invalid user_id format"},
		}, nil
	}

	// Send 2FA notification
	err = flowContext.Services.TwoFactorService.SendTwoFaNotification(
		ctx,
		flowContext.LoginID,
		userID,
		flowContext.Request.TwoFAType,
		flowContext.Request.DeliveryOption,
	)
	if err != nil {
		return &StepResult{
			Error: &Error{Type: "internal_error", Message: "failed to init 2fa: " + err.Error()},
		}, nil
	}

	// Mark as successful
	flowContext.Result.Success = true

	return &StepResult{Continue: true}, nil
}

// DeviceRememberingStep handles device remembering after successful 2FA validation
type DeviceRememberingStep struct{}

func NewDeviceRememberingStep() *DeviceRememberingStep {
	return &DeviceRememberingStep{}
}

func (s *DeviceRememberingStep) Name() string {
	return "device_remembering"
}

func (s *DeviceRememberingStep) Order() int {
	return OrderDeviceRemembering
}

func (s *DeviceRememberingStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	// Skip if RememberDevice is false or device fingerprint is empty
	if !flowContext.Request.RememberDevice || flowContext.Request.DeviceFingerprintStr == "" {
		return true
	}

	// Skip if 2FA was not verified (check from step data)
	if twofaVerified, exists := flowContext.StepData["2fa_verified"].(bool); !exists || !twofaVerified {
		return true
	}

	return false
}

func (s *DeviceRememberingStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	// Link device to login for remembering
	err := flowContext.Services.DeviceService.LinkDeviceToLogin(ctx, flowContext.LoginID, flowContext.Request.DeviceFingerprintStr)
	if err != nil {
		// Log the error but don't fail the login flow
		slog.Error("Failed to link device to login", "error", err, "fingerprint", flowContext.Request.DeviceFingerprint, "loginID", flowContext.LoginID)
		// Continue with the flow even if device linking fails
	} else {
		slog.Info("Device linked to login for remembering", "fingerprint", flowContext.Request.DeviceFingerprint, "loginID", flowContext.LoginID)
	}

	return &StepResult{Continue: true}, nil
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
