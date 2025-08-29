package loginflow

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	// New pluggable flow system
	FlowBuilders *LoginFlowBuilders
}

// Request contains all the data needed for a login flow
type Request struct {
	// Original login fields
	Username          string
	Password          string
	MagicLinkToken    string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string

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

// NewService creates a new login flow service
func NewService(
	loginService *login.LoginService,
	twoFactorService twofa.TwoFactorService,
	deviceService *device.DeviceService,
	tokenService tg.TokenService,
	tokenCookieService *tg.TokenCookieService,
	userMapper mapper.UserMapper,
) *Service {
	// Initialize the pluggable flow builders with the correct signature
	serviceDependencies := &ServiceDependencies{
		LoginService:     loginService,
		TwoFactorService: twoFactorService,
		DeviceService:    deviceService,
		TokenService:     tokenService,
		UserMapper:       userMapper,
	}
	flowBuilders := NewLoginFlowBuilders(serviceDependencies)

	return &Service{
		FlowBuilders: flowBuilders,
	}
}

// ProcessLogin orchestrates the complete login flow using web login flow executor
func (s *Service) ProcessLogin(ctx context.Context, request Request) Result {
	// Set flow type if not already specified
	if request.FlowType == "" {
		request.FlowType = "web"
	}

	// Use the web login flow executor
	flowExecutor := s.FlowBuilders.BuildWebLoginFlow()
	return flowExecutor.Execute(ctx, request)
}

// GenerateLoginTokens generates JWT tokens for a successful login
func (s *Service) GenerateLoginTokens(ctx context.Context, user mapper.User) (map[string]tg.TokenValue, error) {
	// Create JWT tokens using the JwtService
	rootModifications, extraClaims := s.FlowBuilders.services.UserMapper.ToTokenClaims(user)

	tokens, err := s.FlowBuilders.services.TokenService.GenerateTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, nil
}

// ProcessMobileLogin orchestrates the complete mobile login flow using mobile login flow executor
func (s *Service) ProcessMobileLogin(ctx context.Context, request Request) Result {
	// Set flow type if not already specified
	if request.FlowType == "" {
		request.FlowType = "mobile"
	}

	// Use the mobile login flow executor
	flowExecutor := s.FlowBuilders.BuildMobileLoginFlow()
	return flowExecutor.Execute(ctx, request)
}

// GenerateMobileLoginTokens generates mobile JWT tokens for a successful login
func (s *Service) GenerateMobileLoginTokens(ctx context.Context, user mapper.User) (map[string]tg.TokenValue, error) {
	// Create mobile JWT tokens using the JwtService
	rootModifications, extraClaims := s.FlowBuilders.services.UserMapper.ToTokenClaims(user)

	tokens, err := s.FlowBuilders.services.TokenService.GenerateMobileTokens(user.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to generate mobile tokens", "err", err)
		return nil, fmt.Errorf("failed to generate mobile tokens: %w", err)
	}

	return tokens, nil
}

// ProcessLoginByEmail orchestrates the complete login flow using email with email login flow executor
func (s *Service) ProcessLoginByEmail(ctx context.Context, email, password, ipAddress, userAgent, fingerprint string) Result {
	// Convert parameters to unified Request format
	request := Request{
		Username:          email, // Use email as username for email login
		Password:          password,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprint,
		FlowType:          "email",
	}

	// Use the email login flow executor
	flowExecutor := s.FlowBuilders.BuildEmailLoginFlow()
	return flowExecutor.Execute(ctx, request)
}

// ProcessMagicLinkValidation orchestrates the magic link token validation flow using magic link flow executor
func (s *Service) ProcessMagicLinkValidation(ctx context.Context, token, ipAddress, userAgent, fingerprint string) Result {
	// Convert parameters to unified Request format
	request := Request{
		MagicLinkToken:    token,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: fingerprint,
		FlowType:          "magic_link",
	}

	// Use the magic link login flow executor
	flowExecutor := s.FlowBuilders.BuildMagicLinkLoginFlow()
	return flowExecutor.Execute(ctx, request)
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

// Process2FAValidation orchestrates the 2FA validation flow using resumption strategy
func (s *Service) Process2FAValidation(ctx context.Context, request TwoFAValidationRequest) Result {
	// Convert TwoFAValidationRequest to the unified Request format
	flowRequest := Request{
		IsResumption:      true,
		TempToken:         request.TokenString,
		TwoFACode:         request.Passcode,
		TwoFAType:         request.TwoFAType,
		RememberDevice:    request.RememberDevice,
		IPAddress:         request.IPAddress,
		UserAgent:         request.UserAgent,
		DeviceFingerprint: request.DeviceFingerprint,
		FlowType:          "2fa_validation",
	}

	// Use the 2FA validation flow executor
	flowExecutor := s.FlowBuilders.Build2FAValidationFlow()
	return flowExecutor.Execute(ctx, flowRequest)
}

// ProcessMobile2FAValidation orchestrates the mobile 2FA validation flow using mobile 2FA validation flow executor
func (s *Service) ProcessMobile2FAValidation(ctx context.Context, request TwoFAValidationRequest) Result {
	// Convert TwoFAValidationRequest to the unified Request format
	flowRequest := Request{
		IsResumption:      true,
		TempToken:         request.TokenString,
		TwoFACode:         request.Passcode,
		TwoFAType:         request.TwoFAType,
		RememberDevice:    request.RememberDevice,
		IPAddress:         request.IPAddress,
		UserAgent:         request.UserAgent,
		DeviceFingerprint: request.DeviceFingerprint,
		FlowType:          "mobile_2fa_validation",
	}

	// Use the mobile 2FA validation flow executor
	flowExecutor := s.FlowBuilders.BuildMobile2FAValidationFlow()
	return flowExecutor.Execute(ctx, flowRequest)
}

// ProcessUserSwitch orchestrates the user switching flow using user switch flow executor
func (s *Service) ProcessUserSwitch(ctx context.Context, request UserSwitchRequest) Result {
	// Convert UserSwitchRequest to the unified Request format
	flowRequest := Request{
		IsResumption:      true,
		TempToken:         request.TokenString,
		Username:          request.TargetUserID, // Use TargetUserID as Username for user switch validation
		IPAddress:         request.IPAddress,
		UserAgent:         request.UserAgent,
		DeviceFingerprint: request.DeviceFingerprint,
		FlowType:          "user_switch",
	}

	// Use the user switch flow executor
	flowExecutor := s.FlowBuilders.BuildUserSwitchFlow()
	return flowExecutor.Execute(ctx, flowRequest)
}

// TokenRefreshRequest contains the data needed for token refresh
type TokenRefreshRequest struct {
	RefreshToken string
}

// ProcessTokenRefresh orchestrates the token refresh flow for web clients
func (s *Service) ProcessTokenRefresh(ctx context.Context, request TokenRefreshRequest) Result {
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
			Type:    "internal_error",
			Message: "Failed to create tokens",
		}
		return result
	}

	result.Success = true
	result.Tokens = tokens
	return result
}

// ProcessMobileTokenRefresh orchestrates the token refresh flow for mobile clients
func (s *Service) ProcessMobileTokenRefresh(ctx context.Context, request TokenRefreshRequest) Result {
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
			Type:    "internal_error",
			Message: "Failed to create tokens",
		}
		return result
	}

	result.Success = true
	result.Tokens = tokens
	return result
}

// validateRefreshToken validates a refresh token and returns the parsed token
func (s *Service) validateRefreshToken(tokenString string) (*jwt.Token, error) {
	// Parse and validate the refresh token
	token, err := s.FlowBuilders.services.TokenService.ParseToken(tokenString)
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
func (s *Service) getUserFromToken(ctx context.Context, token *jwt.Token) (string, mapper.User, error) {
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

	tokenUser, err := s.FlowBuilders.services.UserMapper.GetUserByUserID(ctx, userUuid)
	if err != nil {
		slog.Error("Failed to get user by user ID", "err", err, "user_id", userIdStr)
		return "", mapper.User{}, fmt.Errorf("failed to get user by user ID: %w", err)
	}

	// Extract claims from token and add them to the user's extra claims
	tokenUser = s.FlowBuilders.services.UserMapper.ExtractTokenClaims(tokenUser, mapClaims)

	return userIdStr, tokenUser, nil
}

// TwoFASendRequest contains the data needed for sending 2FA notifications
type TwoFASendRequest struct {
	TokenString    string
	UserID         string
	TwoFAType      string
	DeliveryOption string
}

// Process2FASend orchestrates the 2FA send notification flow using 2FA send flow executor
func (s *Service) Process2FASend(ctx context.Context, request TwoFASendRequest) Result {
	// Convert TwoFASendRequest to the unified Request format
	flowRequest := Request{
		Username:       request.UserID, // Use UserID as Username for 2FA send
		TwoFAType:      request.TwoFAType,
		DeliveryOption: request.DeliveryOption,
		FlowType:       "2fa_send",
		IsResumption:   true,
		TempToken:      request.TokenString,
	}

	// Use the 2FA send flow executor
	flowExecutor := s.FlowBuilders.Build2FASendFlow()
	return flowExecutor.Execute(ctx, flowRequest)
}

// ProcessLogout orchestrates the logout flow by generating logout tokens
func (s *Service) ProcessLogout(ctx context.Context) Result {
	result := Result{}

	// Generate logout token
	tokenMap, err := s.FlowBuilders.services.TokenService.GenerateLogoutToken("", nil, nil)
	if err != nil {
		slog.Error("Failed to generate logout token", "err", err)
		result.ErrorResponse = &Error{
			Type:    "internal_error",
			Message: "Failed to generate logout token",
		}
		return result
	}

	result.Success = true
	result.Tokens = tokenMap
	return result
}

// GetDeviceExpiration returns the device expiration duration from the device service
func (s *Service) GetDeviceExpiration() time.Duration {
	return s.FlowBuilders.services.DeviceService.GetDeviceExpiration()
}

func (s *Service) checkUserAssociationFlow(claims jwt.Claims) (bool, string) {
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
func (s *Service) GenerateUserAssociationToken(loginID, userID string, userOptions []mapper.User) (map[string]tg.TokenValue, error) {
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
	tempTokenMap, err := s.FlowBuilders.services.TokenService.GenerateTempToken(userID, nil, extraClaims)
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

// ProcessMobileUserLookup orchestrates the mobile user lookup flow using mobile user lookup flow executor
func (s *Service) ProcessMobileUserLookup(ctx context.Context, request MobileUserLookupRequest) Result {
	// Convert MobileUserLookupRequest to the unified Request format
	flowRequest := Request{
		IsResumption: true,
		TempToken:    request.TokenString,
		FlowType:     "mobile_user_lookup",
	}

	// Use the mobile user lookup flow executor
	flowExecutor := s.FlowBuilders.BuildMobileUserLookupFlow()
	return flowExecutor.Execute(ctx, flowRequest)
}
