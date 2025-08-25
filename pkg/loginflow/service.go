package loginflow

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/utils"
)

// Service orchestrates the complete login flow business logic
type Service struct {
	loginService       *login.LoginService
	twoFactorService   twofa.TwoFactorService
	deviceService      device.DeviceService
	tokenService       tg.TokenService
	tokenCookieService tg.TokenCookieService
	userMapper         mapper.UserMapper
}

// Request contains all the data needed for a login flow
type Request struct {
	Username          string
	Password          string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
}

// Result contains the result of a login flow operation
type Result struct {
	Success               bool
	RequiresTwoFA         bool
	RequiresUserSelection bool
	Users                 []mapper.User
	LoginID               uuid.UUID
	TwoFactorMethods      []TwoFactorMethod
	TempToken             *tg.TokenValue
	Tokens                map[string]tg.TokenValue
	DeviceRecognized      bool
	ErrorResponse         *Error
}

// Error represents structured errors from the login flow
type Error struct {
	Type    string
	Message string
	Data    map[string]interface{}
}

func (e *Error) Error() string {
	return e.Message
}

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

// NewService creates a new login flow service
func NewService(
	loginService *login.LoginService,
	twoFactorService twofa.TwoFactorService,
	deviceService device.DeviceService,
	tokenService tg.TokenService,
	tokenCookieService tg.TokenCookieService,
	userMapper mapper.UserMapper,
) *Service {
	return &Service{
		loginService:       loginService,
		twoFactorService:   twoFactorService,
		deviceService:      deviceService,
		tokenService:       tokenService,
		tokenCookieService: tokenCookieService,
		userMapper:         userMapper,
	}
}

// ProcessLogin orchestrates the complete login flow
func (s *Service) ProcessLogin(ctx context.Context, request Request) Result {
	result := Result{}

	// Step 1: Authenticate user credentials
	loginResult, err := s.loginService.Login(ctx, request.Username, request.Password)
	if err != nil {
		slog.Error("Login failed", "err", err)

		// Record the login attempt
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, loginResult.FailureReason)

		// Handle specific error types
		if login.IsAccountLockedError(err) {
			lockoutDuration := s.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)

			result.ErrorResponse = &Error{
				Type:    "account_locked",
				Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
			}
			return result
		}

		if strings.Contains(err.Error(), "password has expired") {
			result.ErrorResponse = &Error{
				Type:    "password_expired",
				Message: "Your password has expired and must be changed before you can log in.",
			}
			return result
		}

		result.ErrorResponse = &Error{
			Type:    "invalid_credentials",
			Message: "Username/Password is wrong",
		}
		return result
	}

	result.LoginID = loginResult.LoginID
	result.Users = loginResult.Users

	// Step 2: Validate users exist
	if len(loginResult.Users) == 0 {
		slog.Error("No user found after login")
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_NO_USER_FOUND)

		result.ErrorResponse = &Error{
			Type:    "no_user_found",
			Message: "Account not active",
		}
		return result
	}

	// Step 3: Parse login ID
	loginID, err := uuid.Parse(loginResult.Users[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", loginResult.Users[0].LoginID, "error", err)
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Invalid login ID",
		}
		return result
	}

	result.LoginID = loginID

	// Step 4: Check device recognition
	deviceRecognized, err := s.CheckDeviceRecognition(ctx, loginID, request.DeviceFingerprint)
	if err != nil {
		slog.Error("Failed to check device recognition", "err", err)
		// Continue with flow, don't fail on device recognition error
	}
	result.DeviceRecognized = deviceRecognized

	// Step 5: Check 2FA requirement
	if !deviceRecognized {
		requires2FA, methods, tempToken, err := s.Check2FARequirement(ctx, loginID, loginResult.Users)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: err.Error(),
			}
			return result
		}

		if requires2FA {
			result.RequiresTwoFA = true
			result.TwoFactorMethods = methods
			result.TempToken = tempToken
			return result
		}
	}

	// Step 6: Check for multiple users
	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, loginID, loginResult.Users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
		}
		return result
	}

	if requiresUserSelection {
		result.RequiresUserSelection = true
		result.TempToken = tempToken
		return result
	}

	// Step 7: Generate tokens for successful login
	tokens, err := s.GenerateLoginTokens(ctx, loginResult.Users[0])
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to generate tokens",
		}
		return result
	}

	// Step 9: Record successful login automatically
	s.RecordSuccessfulLogin(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
}

// CheckDeviceRecognition checks if the device is recognized for the given login
func (s *Service) CheckDeviceRecognition(ctx context.Context, loginID uuid.UUID, fingerprint string) (bool, error) {
	if fingerprint == "" {
		return false, nil
	}

	// Check if this device is linked to the login
	loginDevice, err := s.deviceService.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprint, loginID)
	if err != nil {
		// Device not found or error occurred
		return false, nil
	}

	if loginDevice.IsExpired() {
		// Device link has expired
		return false, nil
	}

	// Device is recognized and not expired
	slog.Info("Device recognized, skipping 2FA", "fingerprint", fingerprint, "loginID", loginID)
	return true, nil
}

// Check2FARequirement checks if 2FA is required for the login
func (s *Service) Check2FARequirement(ctx context.Context, loginID uuid.UUID, users []mapper.User) (bool, []TwoFactorMethod, *tg.TokenValue, error) {
	enabledTwoFAs, err := s.twoFactorService.FindEnabledTwoFAs(ctx, loginID)
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
			options := getUniqueEmailsFromUsers(users)
			curMethod.DeliveryOptions = options
		case twofa.TWO_FACTOR_TYPE_SMS:
			options := getUniquePhonesFromUsers(users)
			curMethod.DeliveryOptions = options
		default:
			curMethod.DeliveryOptions = []DeliveryOption{}
		}
		twoFactorMethods = append(twoFactorMethods, curMethod)
	}

	extraClaims := map[string]interface{}{
		"login_id": loginID.String(),
	}

	// Updated to use the new TokenService interface
	tempTokenMap, err := s.tokenService.GenerateTempToken(users[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return false, nil, nil, fmt.Errorf("failed to generate temp token: %w", err)
	}

	tempToken := tempTokenMap[tg.TEMP_TOKEN_NAME]

	return true, twoFactorMethods, &tempToken, nil
}

// CheckMultipleUsers checks if there are multiple users and handles temp token generation
func (s *Service) CheckMultipleUsers(ctx context.Context, loginID uuid.UUID, users []mapper.User) (bool, *tg.TokenValue, error) {
	if len(users) <= 1 {
		return false, nil, nil
	}

	// Create temp token with the custom claims for user selection
	extraClaims := map[string]interface{}{
		"login_id":     loginID.String(),
		"2fa_verified": true, // This method will only be called if 2FA is not enabled or 2FA validation is passed
	}
	tempTokenMap, err := s.tokenService.GenerateTempToken(users[0].UserId, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return true, nil, fmt.Errorf("failed to generate temp token: %w", err)
	}

	tempToken := tempTokenMap[tg.TEMP_TOKEN_NAME]
	return true, &tempToken, nil
}

// GenerateLoginTokens generates JWT tokens for a successful login
func (s *Service) GenerateLoginTokens(ctx context.Context, user mapper.User) (map[string]tg.TokenValue, error) {
	// Create JWT tokens using the JwtService
	rootModifications, extraClaims := s.loginService.ToTokenClaims(user)

	tokens, err := s.tokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, nil
}

// RecordSuccessfulLogin records a successful login attempt and updates device
func (s *Service) RecordSuccessfulLogin(ctx context.Context, loginID uuid.UUID, ipAddress, userAgent, fingerprint string) {
	// Record successful login attempt
	s.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, true, "")

	// Update device last login time
	if fingerprint != "" {
		_, err := s.deviceService.UpdateDeviceLastLogin(ctx, fingerprint)
		if err != nil {
			slog.Error("Failed to update device last login time", "error", err, "fingerprint", fingerprint)
			// Don't fail the login if we can't update the last login time
		}
	}
}

// ProcessMobileLogin orchestrates the complete mobile login flow
// This is similar to ProcessLogin but generates mobile tokens and doesn't set cookies
func (s *Service) ProcessMobileLogin(ctx context.Context, request Request) Result {
	result := Result{}

	// Step 1: Authenticate user credentials
	loginResult, err := s.loginService.Login(ctx, request.Username, request.Password)
	if err != nil {
		slog.Error("Mobile login failed", "err", err)

		// Record the login attempt
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, loginResult.FailureReason)

		// Handle specific error types
		if login.IsAccountLockedError(err) {
			result.ErrorResponse = &Error{
				Type:    "account_locked",
				Message: "Your account has been temporarily locked. Please try again in 15 minutes.", // Hard-coded for mobile
			}
			return result
		}

		if strings.Contains(err.Error(), "password has expired") {
			result.ErrorResponse = &Error{
				Type:    "password_expired",
				Message: "Your password has expired and must be changed before you can log in.",
			}
			return result
		}

		result.ErrorResponse = &Error{
			Type:    "invalid_credentials",
			Message: "Username/Password is wrong",
		}
		return result
	}

	result.LoginID = loginResult.LoginID
	result.Users = loginResult.Users

	// Step 2: Validate users exist
	if len(loginResult.Users) == 0 {
		slog.Error("No user found after mobile login")
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_NO_USER_FOUND)

		result.ErrorResponse = &Error{
			Type:    "no_user_found",
			Message: "Username/Password is wrong",
		}
		return result
	}

	// Step 3: Parse login ID
	loginID, err := uuid.Parse(loginResult.Users[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", loginResult.Users[0].LoginID, "error", err)
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Invalid login ID",
		}
		return result
	}

	result.LoginID = loginID

	// Step 4: Check device recognition
	deviceRecognized, err := s.CheckDeviceRecognition(ctx, loginID, request.DeviceFingerprint)
	if err != nil {
		slog.Error("Failed to check device recognition", "err", err)
		// Continue with flow, don't fail on device recognition error
	}
	result.DeviceRecognized = deviceRecognized

	// Step 5: Check 2FA requirement (pass nil for ResponseWriter to skip cookie setting)
	if !deviceRecognized {
		requires2FA, methods, tempToken, err := s.Check2FARequirement(ctx, loginID, loginResult.Users)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: err.Error(),
			}
			return result
		}

		if requires2FA {
			result.RequiresTwoFA = true
			result.TwoFactorMethods = methods
			result.TempToken = tempToken
			return result
		}
	}

	// Step 6: Check for multiple users (pass nil for ResponseWriter to skip cookie setting)
	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, loginID, loginResult.Users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
		}
		return result
	}

	if requiresUserSelection {
		result.RequiresUserSelection = true
		result.TempToken = tempToken
		return result
	}

	// Step 7: Generate mobile tokens for successful login
	tokens, err := s.GenerateMobileLoginTokens(ctx, loginResult.Users[0])
	if err != nil {
		slog.Error("Failed to generate mobile tokens", "err", err)
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to create tokens",
		}
		return result
	}

	// Step 8: Record successful login automatically
	s.RecordSuccessfulLogin(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
}

// GenerateMobileLoginTokens generates mobile JWT tokens for a successful login
func (s *Service) GenerateMobileLoginTokens(ctx context.Context, user mapper.User) (map[string]tg.TokenValue, error) {
	// Create mobile JWT tokens using the JwtService
	rootModifications, extraClaims := s.loginService.ToTokenClaims(user)

	tokens, err := s.tokenService.GenerateMobileTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate mobile tokens", "err", err)
		return nil, fmt.Errorf("failed to generate mobile tokens: %w", err)
	}

	return tokens, nil
}

// ProcessLoginByEmail orchestrates the complete login flow using email
func (s *Service) ProcessLoginByEmail(ctx context.Context, email, password, ipAddress, userAgent, fingerprint string) Result {
	result := Result{}

	// Step 1: Authenticate user credentials using email
	loginResult, err := s.loginService.LoginByEmail(ctx, email, password)
	if err != nil {
		slog.Error("Email login failed", "err", err)

		// Record the login attempt
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, ipAddress, userAgent, fingerprint, false, loginResult.FailureReason)

		// Handle specific error types
		if login.IsAccountLockedError(err) {
			lockoutDuration := s.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)

			result.ErrorResponse = &Error{
				Type:    "account_locked",
				Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
			}
			return result
		}

		if strings.Contains(err.Error(), "password has expired") {
			result.ErrorResponse = &Error{
				Type:    "password_expired",
				Message: "Your password has expired and must be changed before you can log in.",
			}
			return result
		}

		result.ErrorResponse = &Error{
			Type:    "invalid_credentials",
			Message: "Email/Password is wrong",
		}
		return result
	}

	// Continue with the rest of the flow using the common logic
	result.LoginID = loginResult.LoginID
	result.Users = loginResult.Users

	// Validate users exist
	if len(loginResult.Users) == 0 {
		slog.Error("No user found after email login")
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_NO_USER_FOUND)

		result.ErrorResponse = &Error{
			Type:    "no_user_found",
			Message: "Account not active",
		}
		return result
	}

	// Parse login ID
	loginID, err := uuid.Parse(loginResult.Users[0].LoginID)
	if err != nil {
		slog.Error("Failed to parse login ID", "loginID", loginResult.Users[0].LoginID, "error", err)
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Invalid login ID",
		}
		return result
	}

	result.LoginID = loginID

	// Continue with device recognition, 2FA, multiple users, and token generation
	// using the same logic as ProcessLogin
	deviceRecognized, err := s.CheckDeviceRecognition(ctx, loginID, fingerprint)
	if err != nil {
		slog.Error("Failed to check device recognition", "err", err)
	}
	result.DeviceRecognized = deviceRecognized

	if !deviceRecognized {
		requires2FA, methods, tempToken, err := s.Check2FARequirement(ctx, loginID, loginResult.Users)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: err.Error(),
			}
			return result
		}

		if requires2FA {
			result.RequiresTwoFA = true
			result.TwoFactorMethods = methods
			result.TempToken = tempToken
			return result
		}
	}

	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, loginID, loginResult.Users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
		}
		return result
	}

	if requiresUserSelection {
		result.RequiresUserSelection = true
		result.TempToken = tempToken
		return result
	}

	tokens, err := s.GenerateLoginTokens(ctx, loginResult.Users[0])
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to generate tokens",
		}
		return result
	}

	// Record successful login automatically
	s.RecordSuccessfulLogin(ctx, loginID, ipAddress, userAgent, fingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
}

// ProcessMagicLinkValidation orchestrates the magic link token validation flow
func (s *Service) ProcessMagicLinkValidation(ctx context.Context, token, ipAddress, userAgent, fingerprint string) Result {
	result := Result{}

	// Step 1: Validate the magic link token
	loginResult, err := s.loginService.ValidateMagicLinkToken(ctx, token)
	if err != nil {
		slog.Error("Magic link validation failed", "err", err)

		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid or expired token",
		}
		return result
	}

	result.LoginID = loginResult.LoginID
	result.Users = loginResult.Users

	// Step 2: Check for multiple users requiring selection
	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, loginResult.LoginID, loginResult.Users)
	if err != nil {
		// Record failed login attempt
		s.loginService.RecordLoginAttempt(ctx, loginResult.LoginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
		}
		return result
	}

	if requiresUserSelection {
		result.RequiresUserSelection = true
		result.TempToken = tempToken
		return result
	}

	// Step 3: Generate tokens for successful login (single user case)
	tokens, err := s.GenerateLoginTokens(ctx, loginResult.Users[0])
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to create tokens",
		}
		return result
	}

	// Step 4: Record successful login automatically
	s.RecordSuccessfulLogin(ctx, loginResult.LoginID, ipAddress, userAgent, fingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
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

// getUniquePhonesFromUsers extracts unique phones from a list of users
func getUniquePhonesFromUsers(users []mapper.User) []DeliveryOption {
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

// UserSwitchRequest contains the data needed for user switching
type UserSwitchRequest struct {
	TokenString       string
	TokenType         string
	TargetUserID      string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
}

// TwoFAValidationRequest contains the data needed for 2FA validation
type TwoFAValidationRequest struct {
	TokenString       string
	TwoFAType         string
	Passcode          string
	RememberDevice    bool
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
}

// Process2FAValidation orchestrates the 2FA validation flow
func (s *Service) Process2FAValidation(ctx context.Context, request TwoFAValidationRequest) Result {
	result := Result{}

	// Step 1: Parse and validate temp token
	token, err := s.tokenService.ParseToken(request.TokenString)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid temp token",
		}
		return result
	}

	// Step 2: Extract login ID from token
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid token claims",
		}
		return result
	}

	loginIDStr, exists := mapClaims["login_id"].(string)
	if !exists {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Missing login_id in token",
		}
		return result
	}

	loginID, err := uuid.Parse(loginIDStr)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid login_id format in token",
		}
		return result
	}

	result.LoginID = loginID

	// Step 3: Validate 2FA passcode
	valid, err := s.twoFactorService.Validate2faPasscode(ctx, loginID, request.TwoFAType, request.Passcode)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "failed to validate 2fa: " + err.Error(),
		}
		return result
	}

	if !valid {
		// Record failed 2FA validation attempt
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)

		// Check if account should be locked
		locked, _, err := s.loginService.IncrementFailedAttemptsAndCheckLock(ctx, loginID)
		if err != nil {
			slog.Error("Failed to increment failed attempts", "err", err)
		}
		if locked {
			lockoutDuration := s.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)
			result.ErrorResponse = &Error{
				Type:    "account_locked",
				Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
			}
			return result
		}
		result.ErrorResponse = &Error{
			Type:    "invalid_2fa",
			Message: "2fa validation failed",
		}
		return result
	}

	// Step 4: Handle device remembering if requested
	if request.RememberDevice && request.DeviceFingerprint != "" {
		err := s.deviceService.LinkDeviceToLogin(ctx, loginID, request.DeviceFingerprint)
		if err != nil {
			slog.Error("Failed to remember device", "err", err)
			// Don't fail the login if we can't remember the device
		}
	}

	// Step 5: Get users for the login ID
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "failed to get user roles: " + err.Error(),
		}
		return result
	}

	if len(users) == 0 {
		slog.Error("No user found after 2fa")
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_NO_USER_FOUND)
		result.ErrorResponse = &Error{
			Type:    "no_user_found",
			Message: "2fa validation failed",
		}
		return result
	}

	result.Users = users

	// Step 6: Check for user association flow
	if extraClaims, exists := mapClaims["extra_claims"].(map[string]interface{}); exists {
		if associateUser, exists := extraClaims["associate_users"]; exists && associateUser.(bool) {
			// This is a user association flow - return special response
			result.RequiresUserSelection = true
			return result
		}
	}

	// Step 7: Check for multiple users
	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, loginID, users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
		}
		return result
	}

	if requiresUserSelection {
		result.RequiresUserSelection = true
		result.TempToken = tempToken
		return result
	}

	// Step 8: Generate tokens for single user
	tokens, err := s.GenerateLoginTokens(ctx, users[0])
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to create access token",
		}
		return result
	}

	// Step 9: Record successful login
	s.RecordSuccessfulLogin(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
}

// ProcessMobile2FAValidation orchestrates the mobile 2FA validation flow
func (s *Service) ProcessMobile2FAValidation(ctx context.Context, request TwoFAValidationRequest) Result {
	result := Result{}

	// Step 1: Parse and validate temp token
	token, err := s.tokenService.ParseToken(request.TokenString)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid temp token",
		}
		return result
	}

	// Step 2: Extract login ID from token
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid token claims",
		}
		return result
	}

	loginIDStr, exists := mapClaims["login_id"].(string)
	if !exists {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Missing login_id in token",
		}
		return result
	}

	loginID, err := uuid.Parse(loginIDStr)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid login_id format in token",
		}
		return result
	}

	result.LoginID = loginID

	// Step 3: Validate 2FA passcode
	valid, err := s.twoFactorService.Validate2faPasscode(ctx, loginID, request.TwoFAType, request.Passcode)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "failed to validate 2fa: " + err.Error(),
		}
		return result
	}

	if !valid {
		// Record failed 2FA validation attempt
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_2FA_VALIDATION_FAILED)

		// Check if account should be locked
		locked, _, err := s.loginService.IncrementFailedAttemptsAndCheckLock(ctx, loginID)
		if err != nil {
			slog.Error("Failed to increment failed attempts", "err", err)
		}
		if locked {
			lockoutDuration := s.loginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			slog.Info("Account locked", "lockoutDuration", lockoutMinutes)
			result.ErrorResponse = &Error{
				Type:    "account_locked",
				Message: "Your account has been temporarily locked. Please try again in " + strconv.Itoa(lockoutMinutes) + " minutes.",
			}
			return result
		}
		result.ErrorResponse = &Error{
			Type:    "invalid_2fa",
			Message: "2fa validation failed",
		}
		return result
	}

	// Step 4: Handle device remembering if requested
	if request.RememberDevice && request.DeviceFingerprint != "" {
		err := s.deviceService.LinkDeviceToLogin(ctx, loginID, request.DeviceFingerprint)
		if err != nil {
			slog.Error("Failed to remember device", "err", err)
			// Don't fail the login if we can't remember the device
		}
	}

	// Step 5: Get users for the login ID
	users, err := s.userMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "failed to get user roles: " + err.Error(),
		}
		return result
	}

	if len(users) == 0 {
		slog.Error("No user found after 2fa")
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_NO_USER_FOUND)
		result.ErrorResponse = &Error{
			Type:    "no_user_found",
			Message: "2fa validation failed",
		}
		return result
	}

	result.Users = users

	// Step 6: Check for multiple users
	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, loginID, users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
		}
		return result
	}

	if requiresUserSelection {
		result.RequiresUserSelection = true
		result.TempToken = tempToken
		return result
	}

	// Step 7: Generate mobile tokens for single user
	tokens, err := s.GenerateMobileLoginTokens(ctx, users[0])
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to create tokens",
		}
		return result
	}

	// Step 8: Record successful login
	s.RecordSuccessfulLogin(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
}

// ProcessUserSwitch orchestrates the user switching flow
func (s *Service) ProcessUserSwitch(ctx context.Context, request UserSwitchRequest) Result {
	result := Result{}

	// Step 1: Parse and validate token
	token, err := s.tokenService.ParseToken(request.TokenString)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid token",
		}
		return result
	}

	// Step 2: Validate 2FA if using temp token
	if request.TokenType == "temp_token" {
		// Extract claims and check 2FA verification
		mapClaims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			result.ErrorResponse = &Error{
				Type:    "invalid_token",
				Message: "Invalid token claims",
			}
			return result
		}

		twofaVerified, exists := mapClaims["2fa_verified"].(bool)
		if !exists || !twofaVerified {
			result.ErrorResponse = &Error{
				Type:    "unauthorized",
				Message: "2FA not verified",
			}
			return result
		}
	}

	// Step 3: Extract login ID from token
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid token claims",
		}
		return result
	}

	loginIDStr, exists := mapClaims["login_id"].(string)
	if !exists {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Missing login_id in token",
		}
		return result
	}

	loginID, err := uuid.Parse(loginIDStr)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: "Invalid login_id format in token",
		}
		return result
	}

	result.LoginID = loginID

	// Step 4: Get all users for the current login
	users, err := s.loginService.GetUsersByLoginId(ctx, loginID)
	if err != nil {
		slog.Error("Failed to get users", "err", err)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to get users",
		}
		return result
	}

	// Step 5: Check if the requested user is in the list
	var targetUser mapper.User
	found := false
	for _, user := range users {
		if user.UserId == request.TargetUserID {
			targetUser = user
			found = true
			break
		}
	}

	if !found {
		result.ErrorResponse = &Error{
			Type:    "forbidden",
			Message: "Not authorized to switch to this user",
		}
		return result
	}

	// Step 6: Generate mobile tokens for the target user
	tokens, err := s.GenerateMobileLoginTokens(ctx, targetUser)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to create tokens",
		}
		return result
	}

	// Step 7: Record successful login
	s.RecordSuccessfulLogin(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint)

	result.Success = true
	result.Tokens = tokens
	result.Users = []mapper.User{targetUser}
	return result
}
