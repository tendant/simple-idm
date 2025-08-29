package loginflow

import (
	"testing"

	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
)

func TestNewLoginFlowBuilders(t *testing.T) {
	// Create mock services - using nil for interfaces since we're just testing builder creation
	var loginService *login.LoginService
	var twoFactorService twofa.TwoFactorService
	var deviceService *device.DeviceService
	var tokenService tg.TokenService
	var userMapper mapper.UserMapper

	serviceDependencies := &ServiceDependencies{
		LoginService:     loginService,
		TwoFactorService: twoFactorService,
		DeviceService:    deviceService,
		TokenService:     tokenService,
		UserMapper:       userMapper,
	}

	builders := NewLoginFlowBuilders(serviceDependencies)

	if builders == nil {
		t.Error("NewLoginFlowBuilders should return a non-nil instance")
	}

	if builders.services == nil {
		t.Error("LoginFlowBuilders should have services initialized")
	}
}

func TestLoginFlowBuilders_BuildWebLoginFlow(t *testing.T) {
	builders := createTestBuilders()
	executor := builders.BuildWebLoginFlow()

	if executor == nil {
		t.Error("BuildWebLoginFlow should return a FlowExecutor")
	}

	steps := executor.registry.GetOrderedSteps()
	if len(steps) == 0 {
		t.Error("Web login flow should have steps")
	}

	// Verify the steps are in the correct order (LoginIDParsingStep was consolidated into CredentialAuthenticationStep)
	expectedSteps := []string{
		"credential_authentication",
		"user_validation",
		"device_recognition",
		"two_fa_requirement",
		"multiple_users",
		"token_generation",
		"success_recording",
	}

	if len(steps) != len(expectedSteps) {
		t.Errorf("Expected %d steps, got %d", len(expectedSteps), len(steps))
	}

	for i, step := range steps {
		if i < len(expectedSteps) && step.Name() != expectedSteps[i] {
			t.Errorf("Expected step %d to be '%s', got '%s'", i, expectedSteps[i], step.Name())
		}
	}
}

func TestLoginFlowBuilders_BuildMobileLoginFlow(t *testing.T) {
	builders := createTestBuilders()
	executor := builders.BuildMobileLoginFlow()

	if executor == nil {
		t.Error("BuildMobileLoginFlow should return a FlowExecutor")
	}

	steps := executor.registry.GetOrderedSteps()
	if len(steps) == 0 {
		t.Error("Mobile login flow should have steps")
	}

	// Mobile flow should be similar to web flow but with mobile token generation
	// We can verify this by checking if token generation step exists
	hasTokenGeneration := false
	for _, step := range steps {
		if step.Name() == "token_generation" {
			hasTokenGeneration = true
			break
		}
	}

	if !hasTokenGeneration {
		t.Error("Mobile login flow should have token generation step")
	}
}

func TestLoginFlowBuilders_BuildEmailLoginFlow(t *testing.T) {
	builders := createTestBuilders()
	executor := builders.BuildEmailLoginFlow()

	if executor == nil {
		t.Error("BuildEmailLoginFlow should return a FlowExecutor")
	}

	steps := executor.registry.GetOrderedSteps()
	if len(steps) == 0 {
		t.Error("Email login flow should have steps")
	}

	// Email flow should have credential authentication with email type
	hasCredentialAuth := false
	for _, step := range steps {
		if step.Name() == "credential_authentication" {
			hasCredentialAuth = true
			break
		}
	}

	if !hasCredentialAuth {
		t.Error("Email login flow should have credential authentication step")
	}
}

func TestLoginFlowBuilders_BuildMagicLinkLoginFlow(t *testing.T) {
	builders := createTestBuilders()
	executor := builders.BuildMagicLinkLoginFlow()

	if executor == nil {
		t.Error("BuildMagicLinkLoginFlow should return a FlowExecutor")
	}

	steps := executor.registry.GetOrderedSteps()
	if len(steps) == 0 {
		t.Error("Magic link login flow should have steps")
	}

	// Magic link flow should skip device recognition and 2FA
	hasDeviceRecognition := false
	hasTwoFA := false
	for _, step := range steps {
		if step.Name() == "device_recognition" {
			hasDeviceRecognition = true
		}
		if step.Name() == "two_fa_requirement" {
			hasTwoFA = true
		}
	}

	if hasDeviceRecognition {
		t.Error("Magic link login flow should not have device recognition step")
	}
	if hasTwoFA {
		t.Error("Magic link login flow should not have 2FA requirement step")
	}
}

func TestLoginFlowBuilders_BuildMinimalLoginFlow(t *testing.T) {
	builders := createTestBuilders()
	executor := builders.BuildMinimalLoginFlow()

	if executor == nil {
		t.Error("BuildMinimalLoginFlow should return a FlowExecutor")
	}

	steps := executor.registry.GetOrderedSteps()
	if len(steps) == 0 {
		t.Error("Minimal login flow should have steps")
	}

	// Minimal flow should have fewer steps than full flow
	if len(steps) >= 7 { // Full flow now has 7 steps (after LoginIDParsingStep consolidation)
		t.Error("Minimal login flow should have fewer steps than full flow")
	}

	// Should have basic steps: credential auth, user validation, token generation, success recording
	// (LoginIDParsingStep was consolidated into CredentialAuthenticationStep)
	expectedSteps := []string{
		"credential_authentication",
		"user_validation",
		"token_generation",
		"success_recording",
	}

	if len(steps) != len(expectedSteps) {
		t.Errorf("Expected %d steps in minimal flow, got %d", len(expectedSteps), len(steps))
	}
}

func TestLoginFlowBuilders_BuildCustomFlow(t *testing.T) {
	builders := createTestBuilders()

	// Create custom steps
	step1 := NewMockStep("custom_step1", 100)
	step2 := NewMockStep("custom_step2", 200)
	customSteps := []LoginFlowStep{step1, step2}

	executor := builders.BuildCustomFlow(customSteps)

	if executor == nil {
		t.Error("BuildCustomFlow should return a FlowExecutor")
	}

	steps := executor.registry.GetOrderedSteps()
	if len(steps) != 2 {
		t.Errorf("Expected 2 custom steps, got %d", len(steps))
	}

	if steps[0].Name() != "custom_step1" {
		t.Errorf("Expected first step to be 'custom_step1', got '%s'", steps[0].Name())
	}
	if steps[1].Name() != "custom_step2" {
		t.Errorf("Expected second step to be 'custom_step2', got '%s'", steps[1].Name())
	}
}

func TestLoginFlowBuilders_BuildFlowByType(t *testing.T) {
	builders := createTestBuilders()

	testCases := []struct {
		flowType FlowType
		expected string
	}{
		{FlowTypeWebLogin, "should build web login flow"},
		{FlowTypeMobileLogin, "should build mobile login flow"},
		{FlowTypeEmailLogin, "should build email login flow"},
		{FlowTypeMagicLink, "should build magic link flow"},
		{FlowTypeMinimal, "should build minimal flow"},
		{FlowTypePasswordless, "should build passwordless flow"},
		{FlowType("unknown"), "should default to web login flow"},
	}

	for _, tc := range testCases {
		executor := builders.BuildFlowByType(tc.flowType)
		if executor == nil {
			t.Errorf("BuildFlowByType(%s) %s", tc.flowType, tc.expected)
		}

		steps := executor.registry.GetOrderedSteps()
		if len(steps) == 0 {
			t.Errorf("BuildFlowByType(%s) should return flow with steps", tc.flowType)
		}
	}
}

func TestLoginFlowBuilders_GetAvailableFlowTypes(t *testing.T) {
	builders := createTestBuilders()
	flowTypes := builders.GetAvailableFlowTypes()

	expectedTypes := []FlowType{
		FlowTypeWebLogin,
		FlowTypeMobileLogin,
		FlowTypeEmailLogin,
		FlowTypeMagicLink,
		FlowTypeMinimal,
		FlowTypePasswordless,
		FlowType2FAValidation,
		FlowTypeMobile2FAValidation,
		FlowTypeUserSwitch,
		FlowTypeMobileUserLookup,
		FlowType2FASend,
	}

	if len(flowTypes) != len(expectedTypes) {
		t.Errorf("Expected %d flow types, got %d", len(expectedTypes), len(flowTypes))
	}

	// Check that all expected types are present
	typeMap := make(map[FlowType]bool)
	for _, ft := range flowTypes {
		typeMap[ft] = true
	}

	for _, expected := range expectedTypes {
		if !typeMap[expected] {
			t.Errorf("Expected flow type '%s' not found in available types", expected)
		}
	}
}

func TestFlowTypeConstants(t *testing.T) {
	if FlowTypeWebLogin != "web_login" {
		t.Errorf("Expected FlowTypeWebLogin to be 'web_login', got '%s'", FlowTypeWebLogin)
	}
	if FlowTypeMobileLogin != "mobile_login" {
		t.Errorf("Expected FlowTypeMobileLogin to be 'mobile_login', got '%s'", FlowTypeMobileLogin)
	}
	if FlowTypeEmailLogin != "email_login" {
		t.Errorf("Expected FlowTypeEmailLogin to be 'email_login', got '%s'", FlowTypeEmailLogin)
	}
	if FlowTypeMagicLink != "magic_link" {
		t.Errorf("Expected FlowTypeMagicLink to be 'magic_link', got '%s'", FlowTypeMagicLink)
	}
	if FlowTypeMinimal != "minimal" {
		t.Errorf("Expected FlowTypeMinimal to be 'minimal', got '%s'", FlowTypeMinimal)
	}
	if FlowTypePasswordless != "passwordless" {
		t.Errorf("Expected FlowTypePasswordless to be 'passwordless', got '%s'", FlowTypePasswordless)
	}
}

// Helper function to create test builders
func createTestBuilders() *LoginFlowBuilders {
	// Create mock services - these don't need to be functional for builder tests
	loginService := &login.LoginService{}
	var twoFactorService twofa.TwoFactorService
	deviceService := &device.DeviceService{}
	var tokenService tg.TokenService
	var userMapper mapper.UserMapper

	serviceDependencies := &ServiceDependencies{
		LoginService:     loginService,
		TwoFactorService: twoFactorService,
		DeviceService:    deviceService,
		TokenService:     tokenService,
		UserMapper:       userMapper,
	}

	return NewLoginFlowBuilders(serviceDependencies)
}
