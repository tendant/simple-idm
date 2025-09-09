package loginflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Mock implementations for testing

type MockLoginFlowStep struct {
	name           string
	order          int
	skipStep       bool
	executeFunc    func(ctx context.Context, flowContext *FlowContext) (*StepResult, error)
	shouldSkipFunc func(ctx context.Context, flowContext *FlowContext) bool
}

func (m *MockLoginFlowStep) Name() string {
	return m.name
}

func (m *MockLoginFlowStep) Order() int {
	return m.order
}

func (m *MockLoginFlowStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, flowContext)
	}
	return &StepResult{Continue: true}, nil
}

func (m *MockLoginFlowStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
	if m.shouldSkipFunc != nil {
		return m.shouldSkipFunc(ctx, flowContext)
	}
	return m.skipStep
}

func NewMockStep(name string, order int) *MockLoginFlowStep {
	return &MockLoginFlowStep{
		name:  name,
		order: order,
	}
}

// Mock services for testing

type MockServiceDependencies struct {
	LoginService     *MockLoginService
	TwoFactorService *MockTwoFactorService
	DeviceService    *MockDeviceService
	TokenService     *MockTokenService
	UserMapper       *MockUserMapper
}

type MockLoginService struct {
	LoginFunc                               func(ctx context.Context, username, password string) (login.LoginResult, error)
	LoginByEmailFunc                        func(ctx context.Context, email, password string) (login.LoginResult, error)
	ValidateMagicLinkTokenFunc              func(ctx context.Context, token string) (login.LoginResult, error)
	RecordLoginAttemptFunc                  func(ctx context.Context, loginID uuid.UUID, ipAddress, userAgent, fingerprint string, success bool, failureReason string)
	GetLockoutDurationFunc                  func() time.Duration
	IncrementFailedAttemptsAndCheckLockFunc func(ctx context.Context, loginID uuid.UUID) (bool, time.Duration, error)
	GetUsersByLoginIdFunc                   func(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error)
	ToTokenClaimsFunc                       func(user mapper.User) (interface{}, map[string]interface{})
}

func (m *MockLoginService) Login(ctx context.Context, username, password string) (login.LoginResult, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, username, password)
	}
	return login.LoginResult{}, nil
}

func (m *MockLoginService) LoginByEmail(ctx context.Context, email, password string) (login.LoginResult, error) {
	if m.LoginByEmailFunc != nil {
		return m.LoginByEmailFunc(ctx, email, password)
	}
	return login.LoginResult{}, nil
}

func (m *MockLoginService) ValidateMagicLinkToken(ctx context.Context, token string) (login.LoginResult, error) {
	if m.ValidateMagicLinkTokenFunc != nil {
		return m.ValidateMagicLinkTokenFunc(ctx, token)
	}
	return login.LoginResult{}, nil
}

func (m *MockLoginService) RecordLoginAttempt(ctx context.Context, loginID uuid.UUID, ipAddress, userAgent, fingerprint string, success bool, failureReason string) {
	if m.RecordLoginAttemptFunc != nil {
		m.RecordLoginAttemptFunc(ctx, loginID, ipAddress, userAgent, fingerprint, success, failureReason)
	}
}

func (m *MockLoginService) GetLockoutDuration() time.Duration {
	if m.GetLockoutDurationFunc != nil {
		return m.GetLockoutDurationFunc()
	}
	return 15 * time.Minute
}

func (m *MockLoginService) IncrementFailedAttemptsAndCheckLock(ctx context.Context, loginID uuid.UUID) (bool, time.Duration, error) {
	if m.IncrementFailedAttemptsAndCheckLockFunc != nil {
		return m.IncrementFailedAttemptsAndCheckLockFunc(ctx, loginID)
	}
	return false, 0, nil
}

func (m *MockLoginService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	if m.GetUsersByLoginIdFunc != nil {
		return m.GetUsersByLoginIdFunc(ctx, loginID)
	}
	return []mapper.User{}, nil
}

func (m *MockLoginService) ToTokenClaims(user mapper.User) (interface{}, map[string]interface{}) {
	if m.ToTokenClaimsFunc != nil {
		return m.ToTokenClaimsFunc(user)
	}
	return nil, map[string]interface{}{}
}

type MockTwoFactorService struct {
	FindEnabledTwoFAsFunc     func(ctx context.Context, loginID uuid.UUID) ([]string, error)
	Validate2faPasscodeFunc   func(ctx context.Context, loginID uuid.UUID, twoFAType, passcode string) (bool, error)
	SendTwoFaNotificationFunc func(ctx context.Context, loginID, userID uuid.UUID, twoFAType, deliveryOption string) error
}

func (m *MockTwoFactorService) FindEnabledTwoFAs(ctx context.Context, loginID uuid.UUID) ([]string, error) {
	if m.FindEnabledTwoFAsFunc != nil {
		return m.FindEnabledTwoFAsFunc(ctx, loginID)
	}
	return []string{}, nil
}

func (m *MockTwoFactorService) Validate2faPasscode(ctx context.Context, loginID uuid.UUID, twoFAType, passcode string) (bool, error) {
	if m.Validate2faPasscodeFunc != nil {
		return m.Validate2faPasscodeFunc(ctx, loginID, twoFAType, passcode)
	}
	return true, nil
}

func (m *MockTwoFactorService) SendTwoFaNotification(ctx context.Context, loginID, userID uuid.UUID, twoFAType, deliveryOption string) error {
	if m.SendTwoFaNotificationFunc != nil {
		return m.SendTwoFaNotificationFunc(ctx, loginID, userID, twoFAType, deliveryOption)
	}
	return nil
}

type MockDeviceService struct {
	FindLoginDeviceByFingerprintAndLoginIDFunc func(ctx context.Context, fingerprint string, loginID uuid.UUID) (interface{}, error)
	LinkDeviceToLoginFunc                      func(ctx context.Context, loginID uuid.UUID, fingerprint string) error
	UpdateDeviceLastLoginFunc                  func(ctx context.Context, fingerprint string) (interface{}, error)
	GetDeviceExpirationFunc                    func() time.Duration
}

func (m *MockDeviceService) FindLoginDeviceByFingerprintAndLoginID(ctx context.Context, fingerprint string, loginID uuid.UUID) (interface{}, error) {
	if m.FindLoginDeviceByFingerprintAndLoginIDFunc != nil {
		return m.FindLoginDeviceByFingerprintAndLoginIDFunc(ctx, fingerprint, loginID)
	}
	return nil, nil
}

func (m *MockDeviceService) LinkDeviceToLogin(ctx context.Context, loginID uuid.UUID, fingerprint string) error {
	if m.LinkDeviceToLoginFunc != nil {
		return m.LinkDeviceToLoginFunc(ctx, loginID, fingerprint)
	}
	return nil
}

func (m *MockDeviceService) UpdateDeviceLastLogin(ctx context.Context, fingerprint string) (interface{}, error) {
	if m.UpdateDeviceLastLoginFunc != nil {
		return m.UpdateDeviceLastLoginFunc(ctx, fingerprint)
	}
	return nil, nil
}

func (m *MockDeviceService) GetDeviceExpiration() time.Duration {
	if m.GetDeviceExpirationFunc != nil {
		return m.GetDeviceExpirationFunc()
	}
	return 30 * 24 * time.Hour
}

type MockTokenService struct {
	GenerateTokensFunc       func(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error)
	GenerateMobileTokensFunc func(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error)
	GenerateTempTokenFunc    func(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error)
	GenerateLogoutTokenFunc  func(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error)
	ParseTokenFunc           func(tokenString string) (*jwt.Token, error)
}

func (m *MockTokenService) GenerateTokens(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error) {
	if m.GenerateTokensFunc != nil {
		return m.GenerateTokensFunc(userID, rootModifications, extraClaims)
	}
	return map[string]tg.TokenValue{}, nil
}

func (m *MockTokenService) GenerateMobileTokens(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error) {
	if m.GenerateMobileTokensFunc != nil {
		return m.GenerateMobileTokensFunc(userID, rootModifications, extraClaims)
	}
	return map[string]tg.TokenValue{}, nil
}

func (m *MockTokenService) GenerateTempToken(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error) {
	if m.GenerateTempTokenFunc != nil {
		return m.GenerateTempTokenFunc(userID, rootModifications, extraClaims)
	}
	return map[string]tg.TokenValue{}, nil
}

func (m *MockTokenService) GenerateLogoutToken(userID string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]tg.TokenValue, error) {
	if m.GenerateLogoutTokenFunc != nil {
		return m.GenerateLogoutTokenFunc(userID, rootModifications, extraClaims)
	}
	return map[string]tg.TokenValue{}, nil
}

func (m *MockTokenService) ParseToken(tokenString string) (*jwt.Token, error) {
	if m.ParseTokenFunc != nil {
		return m.ParseTokenFunc(tokenString)
	}
	return &jwt.Token{}, nil
}

type MockUserMapper struct {
	FindUsersByLoginIDFunc func(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error)
	GetUserByUserIDFunc    func(ctx context.Context, userID uuid.UUID) (mapper.User, error)
	ExtractTokenClaimsFunc func(user mapper.User, claims map[string]interface{}) mapper.User
}

func (m *MockUserMapper) FindUsersByLoginID(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	if m.FindUsersByLoginIDFunc != nil {
		return m.FindUsersByLoginIDFunc(ctx, loginID)
	}
	return []mapper.User{}, nil
}

func (m *MockUserMapper) GetUserByUserID(ctx context.Context, userID uuid.UUID) (mapper.User, error) {
	if m.GetUserByUserIDFunc != nil {
		return m.GetUserByUserIDFunc(ctx, userID)
	}
	return mapper.User{}, nil
}

func (m *MockUserMapper) ExtractTokenClaims(user mapper.User, claims map[string]interface{}) mapper.User {
	if m.ExtractTokenClaimsFunc != nil {
		return m.ExtractTokenClaimsFunc(user, claims)
	}
	return user
}

// Test StepRegistry

func TestStepRegistry_AddStep(t *testing.T) {
	registry := NewStepRegistry()
	step1 := NewMockStep("step1", 100)
	step2 := NewMockStep("step2", 200)

	registry.AddStep(step1).AddStep(step2)

	steps := registry.GetOrderedSteps()
	if len(steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(steps))
	}
	if steps[0].Name() != "step1" {
		t.Errorf("Expected first step to be 'step1', got '%s'", steps[0].Name())
	}
	if steps[1].Name() != "step2" {
		t.Errorf("Expected second step to be 'step2', got '%s'", steps[1].Name())
	}
}

func TestStepRegistry_GetOrderedSteps(t *testing.T) {
	registry := NewStepRegistry()

	// Add steps in reverse order
	step3 := NewMockStep("step3", 300)
	step1 := NewMockStep("step1", 100)
	step2 := NewMockStep("step2", 200)

	registry.AddStep(step3).AddStep(step1).AddStep(step2)

	steps := registry.GetOrderedSteps()
	if len(steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(steps))
	}

	// Should be ordered by Order() value
	if steps[0].Name() != "step1" || steps[0].Order() != 100 {
		t.Errorf("Expected first step to be 'step1' with order 100, got '%s' with order %d", steps[0].Name(), steps[0].Order())
	}
	if steps[1].Name() != "step2" || steps[1].Order() != 200 {
		t.Errorf("Expected second step to be 'step2' with order 200, got '%s' with order %d", steps[1].Name(), steps[1].Order())
	}
	if steps[2].Name() != "step3" || steps[2].Order() != 300 {
		t.Errorf("Expected third step to be 'step3' with order 300, got '%s' with order %d", steps[2].Name(), steps[2].Order())
	}
}

// Test FlowBuilder

func TestFlowBuilder_AddStep(t *testing.T) {
	builder := NewFlowBuilder()
	step1 := NewMockStep("step1", 100)
	step2 := NewMockStep("step2", 200)

	result := builder.AddStep(step1).AddStep(step2)

	if result != builder {
		t.Error("AddStep should return self for chaining")
	}

	steps := builder.registry.GetOrderedSteps()
	if len(steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(steps))
	}
}

func TestFlowBuilder_Build(t *testing.T) {
	builder := NewFlowBuilder()
	step := NewMockStep("step", 100)
	builder.AddStep(step)

	services := &ServiceDependencies{}
	executor := builder.Build(services)

	if executor == nil {
		t.Error("Build should return a FlowExecutor")
	}
	if executor.services != services {
		t.Error("FlowExecutor should have the provided services")
	}
}

// Test FlowExecutor

func TestFlowExecutor_Execute_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{
		Username: "testuser",
		Password: "password",
	}

	step1Called := false
	step2Called := false

	step1 := NewMockStep("step1", 100)
	step1.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step1Called = true
		return &StepResult{
			Continue: true,
			Data:     map[string]interface{}{"step1": "completed"},
		}, nil
	}

	step2 := NewMockStep("step2", 200)
	step2.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step2Called = true
		return &StepResult{
			Continue: true,
			Data:     map[string]interface{}{"step2": "completed"},
		}, nil
	}

	registry := NewStepRegistry()
	registry.AddStep(step1).AddStep(step2)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse != nil {
		t.Errorf("Expected no error, got %v", result.ErrorResponse)
	}
	if !step1Called {
		t.Error("Step1 should have been called")
	}
	if !step2Called {
		t.Error("Step2 should have been called")
	}
}

func TestFlowExecutor_Execute_StepError(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{Username: "testuser"}

	step1Called := false
	step2Called := false

	step1 := NewMockStep("step1", 100)
	step1.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step1Called = true
		return &StepResult{
			Error: &Error{
				Type:    "test_error",
				Message: "Step failed",
			},
		}, nil
	}

	step2 := NewMockStep("step2", 200)
	step2.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step2Called = true
		return &StepResult{Continue: true}, nil
	}

	registry := NewStepRegistry()
	registry.AddStep(step1).AddStep(step2)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse == nil {
		t.Error("Expected error response")
	}
	if result.ErrorResponse.Type != "test_error" {
		t.Errorf("Expected error type 'test_error', got '%s'", result.ErrorResponse.Type)
	}
	if result.ErrorResponse.Message != "Step failed" {
		t.Errorf("Expected error message 'Step failed', got '%s'", result.ErrorResponse.Message)
	}
	if !step1Called {
		t.Error("Step1 should have been called")
	}
	if step2Called {
		t.Error("Step2 should not have been called after error")
	}
}

func TestFlowExecutor_Execute_StepExecutionError(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{Username: "testuser"}

	step1 := NewMockStep("step1", 100)
	step1.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		return nil, errors.New("execution failed")
	}

	registry := NewStepRegistry()
	registry.AddStep(step1)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse == nil {
		t.Error("Expected error response")
	}
	if result.ErrorResponse.Type != "step_execution_error" {
		t.Errorf("Expected error type 'step_execution_error', got '%s'", result.ErrorResponse.Type)
	}
	if result.ErrorResponse.Message == "" {
		t.Error("Expected error message to contain step name")
	}
}

func TestFlowExecutor_Execute_EarlyReturn(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{Username: "testuser"}

	step1Called := false
	step2Called := false

	step1 := NewMockStep("step1", 100)
	step1.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step1Called = true
		return &StepResult{
			Continue:    true,
			EarlyReturn: true,
		}, nil
	}

	step2 := NewMockStep("step2", 200)
	step2.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step2Called = true
		return &StepResult{Continue: true}, nil
	}

	registry := NewStepRegistry()
	registry.AddStep(step1).AddStep(step2)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse != nil {
		t.Errorf("Expected no error, got %v", result.ErrorResponse)
	}
	if !step1Called {
		t.Error("Step1 should have been called")
	}
	if step2Called {
		t.Error("Step2 should not have been called after early return")
	}
}

func TestFlowExecutor_Execute_StepSkipping(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{Username: "testuser"}

	step1Called := false
	step2Called := false
	step3Called := false

	step1 := NewMockStep("step1", 100)
	step1.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step1Called = true
		return &StepResult{Continue: true}, nil
	}

	step2 := NewMockStep("step2", 200)
	step2.skipStep = true // Should be skipped
	step2.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step2Called = true
		return &StepResult{Continue: true}, nil
	}

	step3 := NewMockStep("step3", 300)
	step3.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		step3Called = true
		return &StepResult{Continue: true}, nil
	}

	registry := NewStepRegistry()
	registry.AddStep(step1).AddStep(step2).AddStep(step3)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse != nil {
		t.Errorf("Expected no error, got %v", result.ErrorResponse)
	}
	if !step1Called {
		t.Error("Step1 should have been called")
	}
	if step2Called {
		t.Error("Step2 should have been skipped")
	}
	if !step3Called {
		t.Error("Step3 should have been called")
	}
}

func TestFlowExecutor_Execute_StepDataStorage(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{Username: "testuser"}

	step1 := NewMockStep("step1", 100)
	step1.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		return &StepResult{
			Continue: true,
			Data: map[string]interface{}{
				"key1": "value1",
				"key2": 42,
			},
		}, nil
	}

	step2 := NewMockStep("step2", 200)
	step2.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		// Verify that step data from step1 is available in step2
		if flowContext.StepData["key1"] != "value1" {
			t.Errorf("Expected key1 to be 'value1', got %v", flowContext.StepData["key1"])
		}
		if flowContext.StepData["key2"] != 42 {
			t.Errorf("Expected key2 to be 42, got %v", flowContext.StepData["key2"])
		}
		return &StepResult{Continue: true}, nil
	}

	registry := NewStepRegistry()
	registry.AddStep(step1).AddStep(step2)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse != nil {
		t.Errorf("Expected no error, got %v", result.ErrorResponse)
	}
}

// Test FlowContext initialization

func TestFlowExecutor_Execute_FlowContextInitialization(t *testing.T) {
	// Setup
	ctx := context.Background()
	request := Request{
		Username:             "testuser",
		Password:             "password",
		IPAddress:            "192.168.1.1",
		UserAgent:            "test-agent",
		DeviceFingerprintStr: "test-fingerprint",
	}

	step := NewMockStep("step", 100)
	step.executeFunc = func(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
		// Verify FlowContext is properly initialized
		if flowContext.Request.Username != "testuser" {
			t.Errorf("Expected username 'testuser', got '%s'", flowContext.Request.Username)
		}
		if flowContext.Request.Password != "password" {
			t.Errorf("Expected password 'password', got '%s'", flowContext.Request.Password)
		}
		if flowContext.Request.IPAddress != "192.168.1.1" {
			t.Errorf("Expected IP '192.168.1.1', got '%s'", flowContext.Request.IPAddress)
		}
		if flowContext.Request.UserAgent != "test-agent" {
			t.Errorf("Expected user agent 'test-agent', got '%s'", flowContext.Request.UserAgent)
		}
		if flowContext.Request.DeviceFingerprintStr != "test-fingerprint" {
			t.Errorf("Expected fingerprint 'test-fingerprint', got '%s'", flowContext.Request.DeviceFingerprint)
		}
		if flowContext.Result == nil {
			t.Error("FlowContext.Result should not be nil")
		}
		if flowContext.StepData == nil {
			t.Error("FlowContext.StepData should not be nil")
		}
		if flowContext.Services == nil {
			t.Error("FlowContext.Services should not be nil")
		}
		return &StepResult{Continue: true}, nil
	}

	registry := NewStepRegistry()
	registry.AddStep(step)

	services := &ServiceDependencies{}
	executor := NewFlowExecutor(registry, services)

	// Execute
	result := executor.Execute(ctx, request)

	// Verify
	if result.ErrorResponse != nil {
		t.Errorf("Expected no error, got %v", result.ErrorResponse)
	}
}

// Test predefined step orders

func TestPredefinedStepOrders(t *testing.T) {
	if OrderCredentialAuthentication != 100 {
		t.Errorf("Expected OrderCredentialAuthentication to be 100, got %d", OrderCredentialAuthentication)
	}
	if OrderUserValidation != 200 {
		t.Errorf("Expected OrderUserValidation to be 200, got %d", OrderUserValidation)
	}
	if OrderDeviceRecognition != 400 {
		t.Errorf("Expected OrderDeviceRecognition to be 400, got %d", OrderDeviceRecognition)
	}
	if OrderTwoFARequirement != 500 {
		t.Errorf("Expected OrderTwoFARequirement to be 500, got %d", OrderTwoFARequirement)
	}
	if OrderMultipleUsers != 600 {
		t.Errorf("Expected OrderMultipleUsers to be 600, got %d", OrderMultipleUsers)
	}
	if OrderTokenGeneration != 700 {
		t.Errorf("Expected OrderTokenGeneration to be 700, got %d", OrderTokenGeneration)
	}
	if OrderSuccessRecording != 800 {
		t.Errorf("Expected OrderSuccessRecording to be 800, got %d", OrderSuccessRecording)
	}
}
