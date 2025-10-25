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
	"github.com/tendant/simple-idm/pkg/common"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/utils"
)

// Error type constants
const (
	ErrorTypeAccountLocked      = "account_locked"
	ErrorTypePasswordExpired    = "password_expired"
	ErrorTypeInvalidCredentials = "invalid_credentials"
	ErrorTypeNoUserFound        = "no_user_found"
	ErrorTypeInternalError      = "internal_error"
)

// ServiceDependencies holds all the services required by the login flow
type ServiceDependencies struct {
	LoginService     *login.LoginService
	TwoFactorService twofa.TwoFactorService
	DeviceService    *device.DeviceService
	TokenService     tg.TokenService
	UserMapper       mapper.UserMapper
}

// Service orchestrates the complete login flow business logic
type LoginFlowService struct {
	// Direct service dependencies (no longer using flow builders)
	services *ServiceDependencies
}

// Request contains all the data needed for a login flow
type Request struct {
	// Original login fields
	Username             string
	Password             string
	MagicLinkToken       string
	IPAddress            string
	UserAgent            string
	DeviceFingerprint    device.FingerprintData
	DeviceFingerprintStr string

	// Resumption fields
	IsResumption   bool
	TempToken      string
	TwoFACode      string
	TwoFAType      string
	DeliveryOption string
	RememberDevice bool

	// Flow type indicator
	FlowType string // "web", "mobile", "email", "magic_link", "2fa_validation"
}

// Result contains the result of a login flow operation
type Result struct {
	Success                 bool
	RequiresTwoFA           bool
	RequiresUserSelection   bool
	RequiresUserAssociation bool
	Users                   []mapper.User
	LoginID                 uuid.UUID
	TwoFactorMethods        []TwoFactorMethod
	Tokens                  map[string]tg.TokenValue
	DeviceRecognized        bool
	ErrorResponse           *Error
	UserAssociationUserID   string
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

// NewLoginFlowService creates a new login flow service.
//
// Required services:
//   - loginService: handles authentication logic
//   - tokenService: generates JWT tokens
//   - tokenCookieService: manages token cookies
//   - userMapper: maps between user types
//
// Optional services (can use no-op implementations):
//   - twoFactorService: use twofa.NewNoOpTwoFactorService() if 2FA not needed
//   - deviceService: use device.NewNoOpDeviceService() if device tracking not needed
//
// When using no-op services, related logic will be automatically skipped.
func NewLoginFlowService(
	loginService *login.LoginService,
	twoFactorService twofa.TwoFactorService,
	deviceService *device.DeviceService,
	tokenService tg.TokenService,
	tokenCookieService *tg.TokenCookieService,
	userMapper mapper.UserMapper,
) *LoginFlowService {
	// Store service dependencies directly
	serviceDependencies := &ServiceDependencies{
		LoginService:     loginService,
		TwoFactorService: twoFactorService,
		DeviceService:    deviceService,
		TokenService:     tokenService,
		UserMapper:       userMapper,
	}

	return &LoginFlowService{
		services: serviceDependencies,
	}
}

// ProcessLogin orchestrates the complete login flow using web login
func (s *LoginFlowService) ProcessLogin(ctx context.Context, request Request) Result {
	// Set flow type if not already specified
	if request.FlowType == "" {
		request.FlowType = "web"
	}

	return s.processCredentialLogin(ctx, request, "web")
}

// GenerateLoginTokens generates JWT tokens for a successful login
func (s *LoginFlowService) GenerateLoginTokens(ctx context.Context, user mapper.User) (map[string]tg.TokenValue, error) {
	// Create JWT tokens using the JwtService
	rootModifications, extraClaims := s.services.UserMapper.ToTokenClaims(user)

	tokens, err := s.services.TokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, nil
}

// ProcessMobileLogin orchestrates the complete mobile login flow
func (s *LoginFlowService) ProcessMobileLogin(ctx context.Context, request Request) Result {
	// Set flow type if not already specified
	if request.FlowType == "" {
		request.FlowType = "mobile"
	}

	return s.processCredentialLogin(ctx, request, "mobile")
}

// GenerateMobileLoginTokens generates mobile JWT tokens for a successful login
func (s *LoginFlowService) GenerateMobileLoginTokens(ctx context.Context, user mapper.User) (map[string]tg.TokenValue, error) {
	// Create mobile JWT tokens using the JwtService
	rootModifications, extraClaims := s.services.UserMapper.ToTokenClaims(user)

	tokens, err := s.services.TokenService.GenerateMobileTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate mobile tokens", "err", err)
		return nil, fmt.Errorf("failed to generate mobile tokens: %w", err)
	}

	return tokens, nil
}

// ProcessLoginByEmail orchestrates the complete login flow using email
func (s *LoginFlowService) ProcessLoginByEmail(ctx context.Context, email, password, ipAddress, userAgent string, fingerprint device.FingerprintData) Result {
	// Convert parameters to unified Request format
	request := Request{
		Username:             email, // Use email as username for email login
		Password:             password,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprint,
		DeviceFingerprintStr: device.GenerateFingerprint(fingerprint),
		FlowType:             "email",
	}

	return s.processCredentialLogin(ctx, request, "web")
}

// ProcessMagicLinkValidation orchestrates the magic link token validation flow
func (s *LoginFlowService) ProcessMagicLinkValidation(ctx context.Context, token string, ipAddress string, userAgent string, fingerprint device.FingerprintData) Result {
	// Convert parameters to unified Request format
	request := Request{
		MagicLinkToken:       token,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		DeviceFingerprint:    fingerprint,
		DeviceFingerprintStr: device.GenerateFingerprint(fingerprint),
		FlowType:             "magic_link",
	}

	// 1. Validate magic link token
	loginResult, err := s.services.LoginService.ValidateMagicLinkToken(ctx, token)
	if err != nil {
		slog.Error("Magic link validation failed", "err", err)
		if loginResult.LoginID != uuid.Nil {
			s.recordLoginAttempt(ctx, loginResult.LoginID, request, false, loginResult.FailureReason)
		}
		return s.errorResult(ErrorTypeInvalidCredentials, "Invalid or expired token")
	}

	// 2. Validate user account
	if err := s.validateUserAccount(ctx, loginResult, request); err != nil {
		return s.errorResult(ErrorTypeNoUserFound, "Account not active")
	}

	// Note: Magic link flows skip device recognition and 2FA

	// 3. Check for multiple users
	if s.hasMultipleUsers(ctx, loginResult.LoginID) {
		users, err := s.getMultipleUsers(ctx, loginResult.LoginID)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to get users")
		}
		// Generate temp token for user selection
		extraClaims := map[string]interface{}{
			"login_id": loginResult.LoginID.String(),
		}
		tempToken, err := s.generateTempTokenInternal(ctx, users[0].UserId, extraClaims)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to generate temp token")
		}
		return s.requireUserSelectionResult(loginResult.LoginID, users, tempToken)
	}

	// 4. Generate tokens
	tokens, err := s.generateLoginTokensInternal(ctx, loginResult.Users[0], "web")
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to create tokens")
	}

	// 5. Record success
	s.recordLoginAttempt(ctx, loginResult.LoginID, request, true, "")

	return s.successResult(tokens)
}

// UserSwitchRequest contains the data needed for user switching
type UserSwitchRequest struct {
	TokenString          string
	TokenType            string
	TargetUserID         string
	IPAddress            string
	UserAgent            string
	DeviceFingerprint    device.FingerprintData
	DeviceFingerprintStr string
}

// TwoFAValidationRequest contains the data needed for 2FA validation
type TwoFAValidationRequest struct {
	TokenString          string
	TwoFAType            string
	Passcode             string
	RememberDevice       bool
	IPAddress            string
	UserAgent            string
	DeviceFingerprint    device.FingerprintData
	DeviceFingerprintStr string
}

// Process2FAValidation orchestrates the 2FA validation flow using resumption strategy
func (s *LoginFlowService) Process2FAValidation(ctx context.Context, request TwoFAValidationRequest) Result {
	// 1. Validate temp token
	loginID, _, _, err := s.validateTempTokenInternal(ctx, request.TokenString)
	if err != nil {
		slog.Error("Temp token validation failed", "err", err)
		return s.errorResult("invalid_token", err.Error())
	}

	// 2. Validate 2FA code
	if err := s.validate2FACode(ctx, loginID, request.TwoFAType, request.Passcode); err != nil {
		slog.Error("2FA code validation failed", "err", err)
		return s.errorResult("invalid_2fa_code", "Invalid verification code")
	}

	// 3. Remember device if requested
	if request.RememberDevice {
		if err := s.rememberDevice(ctx, loginID, request.DeviceFingerprintStr); err != nil {
			slog.Warn("Failed to remember device", "err", err)
			// Continue even if device remembering fails
		}
	}

	// 4. Check for multiple users
	if s.hasMultipleUsers(ctx, loginID) {
		users, err := s.getMultipleUsers(ctx, loginID)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to get users")
		}
		// Generate temp token for user selection
		extraClaims := map[string]interface{}{
			"login_id":     loginID.String(),
			"2fa_verified": true,
		}
		tempToken, err := s.generateTempTokenInternal(ctx, users[0].UserId, extraClaims)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to generate temp token")
		}
		return s.requireUserSelectionResult(loginID, users, tempToken)
	}

	// 5. Get user and generate tokens
	user, err := s.getUserFromLoginID(ctx, loginID)
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to get user")
	}

	tokens, err := s.generateLoginTokensInternal(ctx, user, "web")
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to generate tokens")
	}

	// 6. Record success
	req := Request{
		IPAddress:            request.IPAddress,
		UserAgent:            request.UserAgent,
		DeviceFingerprint:    request.DeviceFingerprint,
		DeviceFingerprintStr: request.DeviceFingerprintStr,
	}
	s.recordLoginAttempt(ctx, loginID, req, true, "")

	return s.successResult(tokens)
}

// ProcessMobile2FAValidation orchestrates the mobile 2FA validation flow
func (s *LoginFlowService) ProcessMobile2FAValidation(ctx context.Context, request TwoFAValidationRequest) Result {
	// 1. Validate temp token
	loginID, _, _, err := s.validateTempTokenInternal(ctx, request.TokenString)
	if err != nil {
		slog.Error("Temp token validation failed", "err", err)
		return s.errorResult("invalid_token", err.Error())
	}

	// 2. Validate 2FA code
	if err := s.validate2FACode(ctx, loginID, request.TwoFAType, request.Passcode); err != nil {
		slog.Error("2FA code validation failed", "err", err)
		return s.errorResult("invalid_2fa_code", "Invalid verification code")
	}

	// 3. Remember device if requested
	if request.RememberDevice {
		if err := s.rememberDevice(ctx, loginID, request.DeviceFingerprintStr); err != nil {
			slog.Warn("Failed to remember device", "err", err)
			// Continue even if device remembering fails
		}
	}

	// 4. Check for multiple users
	if s.hasMultipleUsers(ctx, loginID) {
		users, err := s.getMultipleUsers(ctx, loginID)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to get users")
		}
		// Generate temp token for user selection
		extraClaims := map[string]interface{}{
			"login_id":     loginID.String(),
			"2fa_verified": true,
		}
		tempToken, err := s.generateTempTokenInternal(ctx, users[0].UserId, extraClaims)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to generate temp token")
		}
		return s.requireUserSelectionResult(loginID, users, tempToken)
	}

	// 5. Get user and generate mobile tokens
	user, err := s.getUserFromLoginID(ctx, loginID)
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to get user")
	}

	tokens, err := s.generateLoginTokensInternal(ctx, user, "mobile")
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to generate tokens")
	}

	// 6. Record success
	req := Request{
		IPAddress:            request.IPAddress,
		UserAgent:            request.UserAgent,
		DeviceFingerprint:    request.DeviceFingerprint,
		DeviceFingerprintStr: request.DeviceFingerprintStr,
	}
	s.recordLoginAttempt(ctx, loginID, req, true, "")

	return s.successResult(tokens)
}

// ProcessUserSwitch orchestrates the user switching flow
func (s *LoginFlowService) ProcessUserSwitch(ctx context.Context, request UserSwitchRequest) Result {
	// 1. Validate temp token
	loginID, _, _, err := s.validateTempTokenInternal(ctx, request.TokenString)
	if err != nil {
		slog.Error("Temp token validation failed", "err", err)
		return s.errorResult("invalid_token", err.Error())
	}

	// 2. Validate and get target user
	targetUserID, err := uuid.Parse(request.TargetUserID)
	if err != nil {
		slog.Error("Invalid target user ID", "err", err)
		return s.errorResult("invalid_user_id", "Invalid user ID")
	}

	user, err := s.getUserByID(ctx, targetUserID)
	if err != nil {
		slog.Error("Failed to get target user", "err", err)
		return s.errorResult("user_not_found", "User not found")
	}

	// 3. Verify user is associated with the login
	users, err := s.getMultipleUsers(ctx, loginID)
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to verify user association")
	}

	userFound := false
	for _, u := range users {
		if u.UserId == user.UserId {
			userFound = true
			break
		}
	}
	if !userFound {
		slog.Warn("User not associated with login", "userID", user.UserId, "loginID", loginID)
		return s.errorResult("unauthorized", "User not associated with this login")
	}

	// 4. Generate tokens for the selected user
	tokens, err := s.generateLoginTokensInternal(ctx, user, "web")
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to generate tokens")
	}

	// 5. Record success
	req := Request{
		IPAddress:            request.IPAddress,
		UserAgent:            request.UserAgent,
		DeviceFingerprint:    request.DeviceFingerprint,
		DeviceFingerprintStr: request.DeviceFingerprintStr,
	}
	s.recordLoginAttempt(ctx, loginID, req, true, "")

	return s.successResult(tokens)
}

// TokenRefreshRequest contains the data needed for token refresh
type TokenRefreshRequest struct {
	RefreshToken string
}

// ProcessTokenRefresh orchestrates the token refresh flow for web clients
func (s *LoginFlowService) ProcessTokenRefresh(ctx context.Context, request TokenRefreshRequest) Result {
	result := Result{}

	// Step 1: Validate the refresh token
	token, err := s.validateRefreshToken(request.RefreshToken)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: err.Error(),
		}
		return result
	}

	// Step 2: Get user information from token
	_, tokenUser, err := s.getUserFromToken(ctx, token)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: err.Error(),
		}
		return result
	}

	// Step 3: Generate new tokens
	tokens, err := s.GenerateLoginTokens(ctx, tokenUser)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		result.ErrorResponse = &Error{
			Type:    ErrorTypeInternalError,
			Message: "Failed to create tokens",
		}
		return result
	}

	result.Success = true
	result.Tokens = tokens
	return result
}

// ProcessMobileTokenRefresh orchestrates the token refresh flow for mobile clients
func (s *LoginFlowService) ProcessMobileTokenRefresh(ctx context.Context, request TokenRefreshRequest) Result {
	result := Result{}

	// Step 1: Validate the refresh token
	token, err := s.validateRefreshToken(request.RefreshToken)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: err.Error(),
		}
		return result
	}

	// Step 2: Get user information from token
	_, tokenUser, err := s.getUserFromToken(ctx, token)
	if err != nil {
		result.ErrorResponse = &Error{
			Type:    "invalid_token",
			Message: err.Error(),
		}
		return result
	}

	// Step 3: Generate new mobile tokens
	tokens, err := s.GenerateMobileLoginTokens(ctx, tokenUser)
	if err != nil {
		slog.Error("Failed to create mobile tokens", "err", err)
		result.ErrorResponse = &Error{
			Type:    ErrorTypeInternalError,
			Message: "Failed to create tokens",
		}
		return result
	}

	result.Success = true
	result.Tokens = tokens
	return result
}

// validateRefreshToken validates a refresh token and returns the parsed token
func (s *LoginFlowService) validateRefreshToken(tokenString string) (*jwt.Token, error) {
	// Parse and validate the refresh token
	token, err := s.services.TokenService.ParseToken(tokenString)
	if err != nil {
		slog.Error("Invalid refresh token", "err", err)
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Explicitly check token expiration
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("Invalid token claims format")
		return nil, fmt.Errorf("invalid token claims format")
	}

	// Check if token has expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		slog.Error("Missing expiration claim in token")
		return nil, fmt.Errorf("invalid token format: missing expiration")
	}

	expTime := time.Unix(int64(exp), 0)
	if time.Now().After(expTime) {
		slog.Error("Refresh token has expired", "expiry", expTime)
		return nil, fmt.Errorf("refresh token has expired")
	}

	return token, nil
}

// getUserFromToken extracts user information from token claims
func (s *LoginFlowService) getUserFromToken(ctx context.Context, token *jwt.Token) (string, mapper.User, error) {
	// Get user ID from claims
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("Invalid token claims format")
		return "", mapper.User{}, fmt.Errorf("invalid token claims format")
	}

	userIdStr, exists := mapClaims["sub"].(string)
	if !exists {
		slog.Error("Missing user ID in token claims")
		return "", mapper.User{}, fmt.Errorf("invalid token: missing user ID")
	}

	userUuid, err := uuid.Parse(userIdStr)
	if err != nil {
		slog.Error("Failed to parse user ID", "err", err)
		return "", mapper.User{}, fmt.Errorf("failed to parse user ID: %w", err)
	}

	tokenUser, err := s.services.UserMapper.GetUserByUserID(ctx, userUuid)
	if err != nil {
		slog.Error("Failed to get user by user ID", "err", err, "user_id", userIdStr)
		return "", mapper.User{}, fmt.Errorf("failed to get user by user ID: %w", err)
	}

	// Extract claims from token and add them to the user's extra claims
	tokenUser = s.services.UserMapper.ExtractTokenClaims(tokenUser, mapClaims)

	return userIdStr, tokenUser, nil
}

// ============================================================================
// Helper Functions for Simplified Login Flow
// ============================================================================

// authenticateCredentials handles username, email, or magic link authentication
func (s *LoginFlowService) authenticateCredentials(ctx context.Context, req Request) (login.LoginResult, error) {
	var loginResult login.LoginResult
	var err error

	if req.MagicLinkToken != "" {
		// Magic link authentication
		loginResult, err = s.services.LoginService.ValidateMagicLinkToken(ctx, req.MagicLinkToken)
	} else if req.FlowType == "email" {
		// Email-based authentication
		loginResult, err = s.services.LoginService.LoginByEmail(ctx, req.Username, req.Password)
	} else {
		// Username-based authentication
		loginResult, err = s.services.LoginService.Login(ctx, req.Username, req.Password)
	}

	return loginResult, err
}

// validateUserAccount checks if the account has active users
func (s *LoginFlowService) validateUserAccount(ctx context.Context, loginResult login.LoginResult, req Request) error {
	if len(loginResult.Users) == 0 {
		slog.Error("No user found after login")
		s.services.LoginService.RecordLoginAttempt(ctx, loginResult.LoginID, req.IPAddress, req.UserAgent, req.DeviceFingerprintStr, false, login.FAILURE_REASON_NO_USER_FOUND)
		return fmt.Errorf("account not active")
	}
	return nil
}

// recordLoginAttempt logs login attempt to database
func (s *LoginFlowService) recordLoginAttempt(ctx context.Context, loginID uuid.UUID, req Request, success bool, failureReason string) {
	s.services.LoginService.RecordLoginAttempt(ctx, loginID, req.IPAddress, req.UserAgent, req.DeviceFingerprintStr, success, failureReason)
}

// checkDeviceRecognition checks if device is recognized for the login
func (s *LoginFlowService) checkDeviceRecognition(ctx context.Context, loginID uuid.UUID, fingerprintStr string) bool {
	if fingerprintStr == "" {
		return false
	}

	loginDevice, err := s.services.DeviceService.FindLoginDeviceByFingerprintAndLoginID(ctx, fingerprintStr, loginID)
	if err != nil {
		return false
	}

	if loginDevice.IsExpired() {
		return false
	}

	slog.Info("Device recognized", "fingerprint", fingerprintStr, "loginID", loginID)
	return true
}

// check2FARequirement returns whether 2FA is required and available methods
func (s *LoginFlowService) check2FARequirement(ctx context.Context, loginID uuid.UUID) (bool, []TwoFactorMethod, error) {
	enabledTwoFAs, err := s.services.TwoFactorService.FindEnabledTwoFAs(ctx, loginID)
	if err != nil {
		slog.Error("Failed to find enabled 2FA", "loginID", loginID, "error", err)
		return false, nil, fmt.Errorf("failed to find enabled 2FA: %w", err)
	}

	if len(enabledTwoFAs) == 0 {
		slog.Info("2FA is not enabled for login", "loginID", loginID)
		return false, nil, nil
	}

	// Convert enabled 2FA types to TwoFactorMethod format
	methods := s.convertToTwoFactorMethods(ctx, loginID, enabledTwoFAs)
	return true, methods, nil
}

// convertToTwoFactorMethods converts enabled 2FA types to TwoFactorMethod format with delivery options
func (s *LoginFlowService) convertToTwoFactorMethods(ctx context.Context, loginID uuid.UUID, enabledTypes []string) []TwoFactorMethod {
	methods := make([]TwoFactorMethod, 0, len(enabledTypes))

	for _, twoFAType := range enabledTypes {
		method := TwoFactorMethod{
			Type:            twoFAType,
			DeliveryOptions: []DeliveryOption{},
		}

		// Get delivery options based on type
		if twoFAType == "sms" || twoFAType == "email" {
			deliveryOptions := s.getDeliveryOptions(ctx, loginID, twoFAType)
			method.DeliveryOptions = deliveryOptions
		}

		methods = append(methods, method)
	}

	return methods
}

// getDeliveryOptions retrieves delivery options for SMS/email 2FA
func (s *LoginFlowService) getDeliveryOptions(ctx context.Context, loginID uuid.UUID, twoFAType string) []DeliveryOption {
	// Get users for this login
	users, err := s.services.UserMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		slog.Error("Failed to get users for delivery options", "loginID", loginID, "err", err)
		return []DeliveryOption{}
	}

	options := make([]DeliveryOption, 0)
	for _, user := range users {
		if twoFAType == "email" && user.UserInfo.Email != "" {
			options = append(options, DeliveryOption{
				Type:         "email",
				Value:        user.UserInfo.Email,
				UserID:       user.UserId,
				DisplayValue: utils.MaskEmail(user.UserInfo.Email),
				HashedValue:  utils.HashEmail(user.UserInfo.Email),
			})
		} else if twoFAType == "sms" && user.UserInfo.PhoneNumber != "" {
			options = append(options, DeliveryOption{
				Type:         "sms",
				Value:        user.UserInfo.PhoneNumber,
				UserID:       user.UserId,
				DisplayValue: utils.MaskPhone(user.UserInfo.PhoneNumber),
				HashedValue:  utils.HashPhone(user.UserInfo.PhoneNumber),
			})
		}
	}

	return options
}

// rememberDevice links device to login if "remember me" is set
func (s *LoginFlowService) rememberDevice(ctx context.Context, loginID uuid.UUID, fingerprintStr string) error {
	if fingerprintStr == "" {
		return nil
	}

	err := s.services.DeviceService.LinkDeviceToLogin(ctx, loginID, fingerprintStr)
	if err != nil {
		slog.Error("Failed to link device to login", "loginID", loginID, "err", err)
		return err
	}

	slog.Info("Device remembered for login", "loginID", loginID, "fingerprint", fingerprintStr)
	return nil
}

// validate2FACode validates the provided 2FA passcode
func (s *LoginFlowService) validate2FACode(ctx context.Context, loginID uuid.UUID, twoFAType, passcode string) error {
	valid, err := s.services.TwoFactorService.Validate2faPasscode(ctx, loginID, twoFAType, passcode)
	if err != nil {
		slog.Error("2FA validation error", "loginID", loginID, "err", err)
		return fmt.Errorf("2FA validation failed: %w", err)
	}

	if !valid {
		slog.Warn("Invalid 2FA code", "loginID", loginID, "type", twoFAType)
		return fmt.Errorf("invalid verification code")
	}

	return nil
}

// send2FACode sends 2FA code via email/SMS
func (s *LoginFlowService) send2FACode(ctx context.Context, loginID, userID uuid.UUID, twoFAType, deliveryOption string) error {
	err := s.services.TwoFactorService.SendTwoFaNotification(ctx, loginID, userID, twoFAType, deliveryOption)
	if err != nil {
		slog.Error("Failed to send 2FA code", "loginID", loginID, "err", err)
		return fmt.Errorf("failed to send verification code: %w", err)
	}

	slog.Info("2FA code sent", "loginID", loginID, "type", twoFAType)
	return nil
}

// getMultipleUsers returns all users associated with a login
func (s *LoginFlowService) getMultipleUsers(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	users, err := s.services.UserMapper.FindUsersByLoginID(ctx, loginID)
	if err != nil {
		slog.Error("Failed to get users", "loginID", loginID, "err", err)
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	return users, nil
}

// hasMultipleUsers checks if login has multiple associated users
func (s *LoginFlowService) hasMultipleUsers(ctx context.Context, loginID uuid.UUID) bool {
	users, err := s.getMultipleUsers(ctx, loginID)
	if err != nil {
		return false
	}
	return len(users) > 1
}

// getUserByID retrieves a specific user by ID
func (s *LoginFlowService) getUserByID(ctx context.Context, userID uuid.UUID) (mapper.User, error) {
	user, err := s.services.UserMapper.GetUserByUserID(ctx, userID)
	if err != nil {
		slog.Error("Failed to get user by ID", "userID", userID, "err", err)
		return mapper.User{}, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// getUserFromLoginID retrieves the first user for a login ID
func (s *LoginFlowService) getUserFromLoginID(ctx context.Context, loginID uuid.UUID) (mapper.User, error) {
	users, err := s.getMultipleUsers(ctx, loginID)
	if err != nil {
		return mapper.User{}, err
	}
	if len(users) == 0 {
		return mapper.User{}, fmt.Errorf("no users found for login")
	}
	return users[0], nil
}

// generateLoginTokensInternal creates JWT tokens for successful login (web or mobile)
func (s *LoginFlowService) generateLoginTokensInternal(ctx context.Context, user mapper.User, tokenType string) (map[string]tg.TokenValue, error) {
	rootModifications, extraClaims := s.services.UserMapper.ToTokenClaims(user)

	var tokens map[string]tg.TokenValue
	var err error

	if tokenType == "mobile" {
		tokens, err = s.services.TokenService.GenerateMobileTokens(user.UserId, rootModifications, extraClaims)
	} else {
		tokens, err = s.services.TokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	}

	if err != nil {
		slog.Error("Failed to generate tokens", "err", err, "type", tokenType)
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, nil
}

// generateTempTokenInternal creates temporary token for multi-step flows
func (s *LoginFlowService) generateTempTokenInternal(ctx context.Context, userID string, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error) {
	tempTokenMap, err := s.services.TokenService.GenerateTempToken(userID, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return nil, fmt.Errorf("failed to generate temp token: %w", err)
	}
	return tempTokenMap, nil
}

// validateTempTokenInternal validates and extracts claims from temporary token
func (s *LoginFlowService) validateTempTokenInternal(ctx context.Context, tokenString string) (loginID uuid.UUID, claims map[string]interface{}, user mapper.User, err error) {
	// Parse and validate the temp token
	token, parseErr := s.services.TokenService.ParseToken(tokenString)
	if parseErr != nil {
		slog.Error("Invalid temp token", "err", parseErr)
		return uuid.Nil, nil, mapper.User{}, fmt.Errorf("invalid temp token: %w", parseErr)
	}

	// Extract user from token
	_, tokenUser, getUserErr := s.getUserFromToken(ctx, token)
	if getUserErr != nil {
		return uuid.Nil, nil, mapper.User{}, fmt.Errorf("failed to get user from token: %w", getUserErr)
	}

	// Extract claims
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, nil, mapper.User{}, fmt.Errorf("invalid token claims format")
	}

	// Extract login_id from extra_claims
	var loginIDStr string
	if extraClaims, exists := mapClaims["extra_claims"].(map[string]interface{}); exists {
		if lid, ok := extraClaims["login_id"].(string); ok {
			loginIDStr = lid
		}
	}

	if loginIDStr == "" {
		slog.Error("Missing login_id in token claims")
		return uuid.Nil, nil, mapper.User{}, fmt.Errorf("missing login_id in token")
	}

	parsedLoginID, parseErr := uuid.Parse(loginIDStr)
	if parseErr != nil {
		return uuid.Nil, nil, mapper.User{}, fmt.Errorf("invalid login_id: %w", parseErr)
	}

	return parsedLoginID, mapClaims, tokenUser, nil
}

// errorResult creates a Result with error response
func (s *LoginFlowService) errorResult(errorType, message string) Result {
	return Result{
		Success: false,
		ErrorResponse: &Error{
			Type:    errorType,
			Message: message,
		},
	}
}

// require2FAResult creates a Result requiring 2FA validation
func (s *LoginFlowService) require2FAResult(loginID uuid.UUID, methods []TwoFactorMethod, tempToken map[string]tg.TokenValue) Result {
	return Result{
		Success:          false,
		RequiresTwoFA:    true,
		LoginID:          loginID,
		TwoFactorMethods: methods,
		Tokens:           tempToken,
	}
}

// requireUserSelectionResult creates a Result requiring user selection
func (s *LoginFlowService) requireUserSelectionResult(loginID uuid.UUID, users []mapper.User, tempToken map[string]tg.TokenValue) Result {
	return Result{
		Success:               false,
		RequiresUserSelection: true,
		LoginID:               loginID,
		Users:                 users,
		Tokens:                tempToken,
	}
}

// successResult creates a successful Result with tokens
func (s *LoginFlowService) successResult(tokens map[string]tg.TokenValue) Result {
	return Result{
		Success: true,
		Tokens:  tokens,
	}
}

// ============================================================================
// Core Login Flow Template
// ============================================================================

// processCredentialLogin handles the common login flow for web/mobile/email
func (s *LoginFlowService) processCredentialLogin(ctx context.Context, req Request, tokenType string) Result {
	// 1. Authenticate credentials
	loginResult, err := s.authenticateCredentials(ctx, req)
	if err != nil {
		slog.Error("Login failed", "err", err, "type", req.FlowType)

		// Record failed attempt if we have loginID
		if loginResult.LoginID != uuid.Nil {
			s.recordLoginAttempt(ctx, loginResult.LoginID, req, false, loginResult.FailureReason)
		}

		// Handle specific error types
		if login.IsAccountLockedError(err) {
			lockoutDuration := s.services.LoginService.GetLockoutDuration()
			lockoutMinutes := int(lockoutDuration / time.Minute)
			return s.errorResult(ErrorTypeAccountLocked,
				"Your account has been temporarily locked. Please try again in "+strconv.Itoa(lockoutMinutes)+" minutes.")
		}

		if strings.Contains(err.Error(), "password has expired") {
			return s.errorResult(ErrorTypePasswordExpired,
				"Your password has expired, please reset your password through the forgot password link.")
		}

		errorMessage := "Username/Password is wrong"
		if req.FlowType == "email" {
			errorMessage = "Email/Password is wrong"
		}

		return s.errorResult(ErrorTypeInvalidCredentials, errorMessage)
	}

	// 2. Validate user account
	if err := s.validateUserAccount(ctx, loginResult, req); err != nil {
		return s.errorResult(ErrorTypeNoUserFound, "Account not active")
	}

	// 3. Check device recognition
	deviceRecognized := s.checkDeviceRecognition(ctx, loginResult.LoginID, req.DeviceFingerprintStr)

	// 4. Check 2FA requirement (skip if device is recognized)
	if !deviceRecognized {
		needs2FA, methods, err := s.check2FARequirement(ctx, loginResult.LoginID)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to check 2FA requirement")
		}
		if needs2FA {
			// Generate temp token for 2FA flow
			extraClaims := map[string]interface{}{
				"login_id": loginResult.LoginID.String(),
			}
			tempToken, err := s.generateTempTokenInternal(ctx, loginResult.Users[0].UserId, extraClaims)
			if err != nil {
				return s.errorResult(ErrorTypeInternalError, "Failed to generate temp token")
			}
			return s.require2FAResult(loginResult.LoginID, methods, tempToken)
		}
	}

	// 5. Check for multiple users
	if s.hasMultipleUsers(ctx, loginResult.LoginID) {
		users, err := s.getMultipleUsers(ctx, loginResult.LoginID)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to get users")
		}
		// Generate temp token for user selection
		extraClaims := map[string]interface{}{
			"login_id":     loginResult.LoginID.String(),
			"2fa_verified": true,
		}
		tempToken, err := s.generateTempTokenInternal(ctx, users[0].UserId, extraClaims)
		if err != nil {
			return s.errorResult(ErrorTypeInternalError, "Failed to generate temp token")
		}
		return s.requireUserSelectionResult(loginResult.LoginID, users, tempToken)
	}

	// 6. Generate tokens
	tokens, err := s.generateLoginTokensInternal(ctx, loginResult.Users[0], tokenType)
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to create tokens")
	}

	// 7. Record success
	s.recordLoginAttempt(ctx, loginResult.LoginID, req, true, "")

	return s.successResult(tokens)
}

// TwoFASendRequest contains the data needed for sending 2FA notifications
type TwoFASendRequest struct{
	TokenString    string
	UserID         string
	TwoFAType      string
	DeliveryOption string
}

// Process2FASend orchestrates the 2FA send notification flow
func (s *LoginFlowService) Process2FASend(ctx context.Context, request TwoFASendRequest) Result {
	// 1. Validate temp token
	loginID, _, _, err := s.validateTempTokenInternal(ctx, request.TokenString)
	if err != nil {
		slog.Error("Temp token validation failed", "err", err)
		return s.errorResult("invalid_token", err.Error())
	}

	// 2. Parse user ID
	userID, err := uuid.Parse(request.UserID)
	if err != nil {
		slog.Error("Invalid user ID", "err", err)
		return s.errorResult("invalid_user_id", "Invalid user ID")
	}

	// 3. Send 2FA code
	if err := s.send2FACode(ctx, loginID, userID, request.TwoFAType, request.DeliveryOption); err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to send verification code")
	}

	return Result{Success: true}
}

// ProcessLogout orchestrates the logout flow by generating logout tokens
func (s *LoginFlowService) ProcessLogout(ctx context.Context) Result {
	result := Result{}

	// Generate logout token
	tokenMap, err := s.services.TokenService.GenerateLogoutToken("", nil, nil)
	if err != nil {
		slog.Error("Failed to generate logout token", "err", err)
		result.ErrorResponse = &Error{
			Type:    ErrorTypeInternalError,
			Message: "Failed to generate logout token",
		}
		return result
	}

	result.Success = true
	result.Tokens = tokenMap
	return result
}

// GetDeviceExpiration returns the device expiration duration from the device service
func (s *LoginFlowService) GetDeviceExpiration() time.Duration {
	return s.services.DeviceService.GetDeviceExpiration()
}

func (s *LoginFlowService) checkUserAssociationFlow(claims jwt.Claims) (bool, string) {
	if mapClaims, ok := claims.(jwt.MapClaims); ok {
		slog.Info("Claims", "claims", mapClaims)

		// User options are nested inside extra_claims
		if extraClaims, exists := mapClaims["extra_claims"].(map[string]interface{}); exists {
			slog.Info("Extra claims", "extraClaims", extraClaims)

			// Extract user options from extra_claims
			if associateUser, exists := extraClaims["associate_users"]; exists {
				slog.Info("Current 2FA is in associate user flow", "associateUser", associateUser)
				userID, err := common.GetUserIDFromClaims(claims)
				if err != nil {
					slog.Error("Failed to get user ID from claims", "err", err)
					return false, ""
				}
				return associateUser.(bool), userID
			}
		}
	}
	return false, ""
}

// GenerateUserAssociationToken generates a temp token for user association flow
func (s *LoginFlowService) GenerateUserAssociationToken(loginID, userID string, userOptions []mapper.User) (map[string]tg.TokenValue, error) {
	// Prepare extra claims for the temp token
	extraClaims := map[string]interface{}{
		"login_id":     loginID,
		"2fa_verified": true,
	}

	// Add user options to extra claims
	if userOptions != nil {
		extraClaims["user_options"] = userOptions
	}

	// Generate a temporary token with the necessary claims
	tempTokenMap, err := s.services.TokenService.GenerateTempToken(userID, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return nil, fmt.Errorf("failed to generate temp token: %w", err)
	}

	return tempTokenMap, nil
}

// MobileUserLookupRequest contains the data needed for mobile user lookup
type MobileUserLookupRequest struct {
	TokenString string
	TokenType   string
}

// ProcessMobileUserLookup orchestrates the mobile user lookup flow
func (s *LoginFlowService) ProcessMobileUserLookup(ctx context.Context, request MobileUserLookupRequest) Result {
	// 1. Validate temp token
	loginID, _, _, err := s.validateTempTokenInternal(ctx, request.TokenString)
	if err != nil {
		slog.Error("Temp token validation failed", "err", err)
		return s.errorResult("invalid_token", err.Error())
	}

	// 2. Get users for this login
	users, err := s.getMultipleUsers(ctx, loginID)
	if err != nil {
		return s.errorResult(ErrorTypeInternalError, "Failed to get users")
	}

	return Result{
		Success: true,
		Users:   users,
		LoginID: loginID,
	}
}
