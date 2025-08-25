package loginflow

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/common"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
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
	TwoFactorMethods      []common.TwoFactorMethod
	TempToken             *tg.TokenValue
	Tokens                map[string]tg.TokenValue
	DeviceRecognized      bool
	ErrorResponse         *Error
}

// Error represents structured errors from the login flow
type Error struct {
	Type    string
	Message string
	Code    int
	Data    map[string]interface{}
}

func (e *Error) Error() string {
	return e.Message
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
func (s *Service) ProcessLogin(ctx context.Context, w http.ResponseWriter, request Request) Result {
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
				Code:    http.StatusTooManyRequests,
			}
			return result
		}

		if strings.Contains(err.Error(), "password has expired") {
			result.ErrorResponse = &Error{
				Type:    "password_expired",
				Message: "Your password has expired and must be changed before you can log in.",
				Code:    http.StatusForbidden,
			}
			return result
		}

		result.ErrorResponse = &Error{
			Type:    "invalid_credentials",
			Message: "Username/Password is wrong",
			Code:    http.StatusBadRequest,
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
			Code:    http.StatusForbidden,
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
			Code:    http.StatusInternalServerError,
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
		requires2FA, methods, tempToken, err := s.Check2FARequirement(ctx, w, loginID, loginResult.Users)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: err.Error(),
				Code:    http.StatusInternalServerError,
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
	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, w, loginID, loginResult.Users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
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
			Code:    http.StatusInternalServerError,
		}
		return result
	}

	// Step 8: Set tokens in cookies
	if w != nil {
		err = s.tokenCookieService.SetTokensCookie(w, tokens)
		if err != nil {
			slog.Error("Failed to set access token cookie", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, request.IPAddress, request.UserAgent, request.DeviceFingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: "Failed to set access token cookie",
				Code:    http.StatusInternalServerError,
			}
			return result
		}
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
func (s *Service) Check2FARequirement(ctx context.Context, w http.ResponseWriter, loginID uuid.UUID, users []mapper.User) (bool, []common.TwoFactorMethod, *tg.TokenValue, error) {
	enabled, commonMethods, tempToken, err := common.Check2FAEnabled(
		ctx,
		w,
		loginID,
		users,
		s.twoFactorService,
		s.tokenService,
		s.tokenCookieService,
		false, // Not associate user in this API
	)
	if err != nil {
		return false, nil, nil, fmt.Errorf("failed to check 2FA: %w", err)
	}

	return enabled, commonMethods, tempToken, nil
}

// CheckMultipleUsers checks if there are multiple users and handles temp token generation
func (s *Service) CheckMultipleUsers(ctx context.Context, w http.ResponseWriter, loginID uuid.UUID, users []mapper.User) (bool, *tg.TokenValue, error) {
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

	// Only set cookie if a writer is provided (web flow)
	if w != nil {
		err = s.tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return true, nil, fmt.Errorf("failed to set temp token cookie: %w", err)
		}
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

// ProcessLoginByEmail orchestrates the complete login flow using email
func (s *Service) ProcessLoginByEmail(ctx context.Context, w http.ResponseWriter, email, password, ipAddress, userAgent, fingerprint string) Result {
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
				Code:    http.StatusTooManyRequests,
			}
			return result
		}

		if strings.Contains(err.Error(), "password has expired") {
			result.ErrorResponse = &Error{
				Type:    "password_expired",
				Message: "Your password has expired and must be changed before you can log in.",
				Code:    http.StatusForbidden,
			}
			return result
		}

		result.ErrorResponse = &Error{
			Type:    "invalid_credentials",
			Message: "Email/Password is wrong",
			Code:    http.StatusBadRequest,
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
			Code:    http.StatusForbidden,
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
			Code:    http.StatusInternalServerError,
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
		requires2FA, methods, tempToken, err := s.Check2FARequirement(ctx, w, loginID, loginResult.Users)
		if err != nil {
			slog.Error("Failed to check 2FA", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: err.Error(),
				Code:    http.StatusInternalServerError,
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

	requiresUserSelection, tempToken, err := s.CheckMultipleUsers(ctx, w, loginID, loginResult.Users)
	if err != nil {
		s.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
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
			Code:    http.StatusInternalServerError,
		}
		return result
	}

	if w != nil {
		err = s.tokenCookieService.SetTokensCookie(w, tokens)
		if err != nil {
			slog.Error("Failed to set access token cookie", "err", err)
			s.loginService.RecordLoginAttempt(ctx, loginID, ipAddress, userAgent, fingerprint, false, login.FAILURE_REASON_INTERNAL_ERROR)

			result.ErrorResponse = &Error{
				Type:    "internal_error",
				Message: "Failed to set access token cookie",
				Code:    http.StatusInternalServerError,
			}
			return result
		}
	}

	// Record successful login automatically
	s.RecordSuccessfulLogin(ctx, loginID, ipAddress, userAgent, fingerprint)

	result.Success = true
	result.Tokens = tokens
	return result
}
