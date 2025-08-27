package loginflow

import (
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
)

// LoginFlowBuilders provides pre-configured flow builders for different login types
type LoginFlowBuilders struct {
	services *ServiceDependencies
}

// NewLoginFlowBuilders creates a new instance of LoginFlowBuilders
func NewLoginFlowBuilders(
	loginService *login.LoginService,
	twoFactorService twofa.TwoFactorService,
	deviceService *device.DeviceService,
	tokenService tg.TokenService,
	userMapper mapper.UserMapper,
) *LoginFlowBuilders {
	// For now, we'll store the concrete services directly
	// This avoids interface compatibility issues during the initial refactoring
	services := &ServiceDependencies{
		LoginService:     loginService,
		TwoFactorService: twoFactorService,
		DeviceService:    deviceService,
		TokenService:     tokenService,
		UserMapper:       userMapper,
	}

	return &LoginFlowBuilders{
		services: services,
	}
}

// BuildWebLoginFlow creates a standard web login flow
func (b *LoginFlowBuilders) BuildWebLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("username")).
		AddStep(NewUserValidationStep()).
		AddStep(NewLoginIDParsingStep()).
		AddStep(NewDeviceRecognitionStep()).
		AddStep(NewTwoFARequirementStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildMobileLoginFlow creates a mobile login flow
func (b *LoginFlowBuilders) BuildMobileLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("username")).
		AddStep(NewUserValidationStep()).
		AddStep(NewLoginIDParsingStep()).
		AddStep(NewDeviceRecognitionStep()).
		AddStep(NewTwoFARequirementStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("mobile")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildEmailLoginFlow creates an email-based login flow
func (b *LoginFlowBuilders) BuildEmailLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("email")).
		AddStep(NewUserValidationStep()).
		AddStep(NewLoginIDParsingStep()).
		AddStep(NewDeviceRecognitionStep()).
		AddStep(NewTwoFARequirementStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildMagicLinkLoginFlow creates a magic link validation flow
func (b *LoginFlowBuilders) BuildMagicLinkLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("magic_link")).
		AddStep(NewUserValidationStep()).
		AddStep(NewLoginIDParsingStep()).
		// Note: Magic link flows typically skip device recognition and 2FA
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildCustomFlow creates a custom flow with specified steps
func (b *LoginFlowBuilders) BuildCustomFlow(steps []LoginFlowStep) *FlowExecutor {
	builder := NewFlowBuilder()
	for _, step := range steps {
		builder.AddStep(step)
	}
	return builder.Build(b.services)
}

// BuildMinimalLoginFlow creates a minimal login flow (just credential auth and token generation)
func (b *LoginFlowBuilders) BuildMinimalLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("username")).
		AddStep(NewUserValidationStep()).
		AddStep(NewLoginIDParsingStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildPasswordlessLoginFlow creates a passwordless login flow (no 2FA, device recognition only)
func (b *LoginFlowBuilders) BuildPasswordlessLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("username")).
		AddStep(NewUserValidationStep()).
		AddStep(NewLoginIDParsingStep()).
		AddStep(NewDeviceRecognitionStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// FlowType represents different types of login flows
type FlowType string

const (
	FlowTypeWebLogin     FlowType = "web_login"
	FlowTypeMobileLogin  FlowType = "mobile_login"
	FlowTypeEmailLogin   FlowType = "email_login"
	FlowTypeMagicLink    FlowType = "magic_link"
	FlowTypeMinimal      FlowType = "minimal"
	FlowTypePasswordless FlowType = "passwordless"
)

// BuildFlowByType creates a flow executor based on the specified flow type
func (b *LoginFlowBuilders) BuildFlowByType(flowType FlowType) *FlowExecutor {
	switch flowType {
	case FlowTypeWebLogin:
		return b.BuildWebLoginFlow()
	case FlowTypeMobileLogin:
		return b.BuildMobileLoginFlow()
	case FlowTypeEmailLogin:
		return b.BuildEmailLoginFlow()
	case FlowTypeMagicLink:
		return b.BuildMagicLinkLoginFlow()
	case FlowTypeMinimal:
		return b.BuildMinimalLoginFlow()
	case FlowTypePasswordless:
		return b.BuildPasswordlessLoginFlow()
	default:
		// Default to web login flow
		return b.BuildWebLoginFlow()
	}
}

// GetAvailableFlowTypes returns all available flow types
func (b *LoginFlowBuilders) GetAvailableFlowTypes() []FlowType {
	return []FlowType{
		FlowTypeWebLogin,
		FlowTypeMobileLogin,
		FlowTypeEmailLogin,
		FlowTypeMagicLink,
		FlowTypeMinimal,
		FlowTypePasswordless,
	}
}
