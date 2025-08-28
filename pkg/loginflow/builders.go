package loginflow

// LoginFlowBuilders provides pre-configured flow builders for different login types
type LoginFlowBuilders struct {
	services *ServiceDependencies
}

// NewLoginFlowBuilders creates a new instance of LoginFlowBuilders
func NewLoginFlowBuilders(services *ServiceDependencies) *LoginFlowBuilders {
	return &LoginFlowBuilders{
		services: services,
	}
}

// BuildWebLoginFlow creates a standard web login flow
func (b *LoginFlowBuilders) BuildWebLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("username")).
		AddStep(NewUserValidationStep()).
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
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildPasswordlessLoginFlow creates a passwordless login flow (no 2FA, device recognition only)
func (b *LoginFlowBuilders) BuildPasswordlessLoginFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewCredentialAuthenticationStep("username")).
		AddStep(NewUserValidationStep()).
		AddStep(NewDeviceRecognitionStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// Build2FAValidationFlow creates a 2FA validation flow using resumption strategy
func (b *LoginFlowBuilders) Build2FAValidationFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewTempTokenValidationStep()).
		AddStep(NewTwoFAValidationStep()).
		AddStep(NewDeviceRememberingStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildMobile2FAValidationFlow creates a mobile 2FA validation flow using resumption strategy
func (b *LoginFlowBuilders) BuildMobile2FAValidationFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewTempTokenValidationStep()).
		AddStep(NewTwoFAValidationStep()).
		AddStep(NewDeviceRememberingStep()).
		AddStep(NewMultipleUsersStep()).
		AddStep(NewTokenGenerationStep("mobile")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildUserSwitchFlow creates a user switching flow
func (b *LoginFlowBuilders) BuildUserSwitchFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewTempTokenValidationStep()).
		AddStep(NewUserSwitchValidationStep()).
		AddStep(NewTokenGenerationStep("web")).
		AddStep(NewSuccessRecordingStep()).
		Build(b.services)
}

// BuildMobileUserLookupFlow creates a mobile user lookup flow
func (b *LoginFlowBuilders) BuildMobileUserLookupFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewTempTokenValidationStep()).
		AddStep(NewUserLookupStep()).
		Build(b.services)
}

// Build2FASendFlow creates a 2FA send flow
func (b *LoginFlowBuilders) Build2FASendFlow() *FlowExecutor {
	return NewFlowBuilder().
		AddStep(NewTempTokenValidationStep()).
		AddStep(NewTwoFASendStep()).
		Build(b.services)
}

// FlowType represents different types of login flows
type FlowType string

const (
	FlowTypeWebLogin            FlowType = "web_login"
	FlowTypeMobileLogin         FlowType = "mobile_login"
	FlowTypeEmailLogin          FlowType = "email_login"
	FlowTypeMagicLink           FlowType = "magic_link"
	FlowTypeMinimal             FlowType = "minimal"
	FlowTypePasswordless        FlowType = "passwordless"
	FlowType2FAValidation       FlowType = "2fa_validation"
	FlowTypeMobile2FAValidation FlowType = "mobile_2fa_validation"
	FlowTypeUserSwitch          FlowType = "user_switch"
	FlowTypeMobileUserLookup    FlowType = "mobile_user_lookup"
	FlowType2FASend             FlowType = "2fa_send"
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
	case FlowType2FAValidation:
		return b.Build2FAValidationFlow()
	case FlowTypeMobile2FAValidation:
		return b.BuildMobile2FAValidationFlow()
	case FlowTypeUserSwitch:
		return b.BuildUserSwitchFlow()
	case FlowTypeMobileUserLookup:
		return b.BuildMobileUserLookupFlow()
	case FlowType2FASend:
		return b.Build2FASendFlow()
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
		FlowType2FAValidation,
		FlowTypeMobile2FAValidation,
		FlowTypeUserSwitch,
		FlowTypeMobileUserLookup,
		FlowType2FASend,
	}
}
