# Login Flow Architecture Documentation

This package provides a pluggable, orderable login flow system that allows for flexible authentication workflows. The architecture is built around the concept of discrete steps that can be composed into different flow types.

## Table of Contents

- [Overview](#overview)
- [Core Components](#core-components)
- [Flow Architecture](#flow-architecture)
- [Builder Pattern](#builder-pattern)
- [Pre-configured Flows](#pre-configured-flows)
- [Creating Custom Flows](#creating-custom-flows)
- [Step Implementation](#step-implementation)
- [Usage Examples](#usage-examples)
- [Testing](#testing)

## Overview

The login flow system transforms the traditional monolithic login process into a series of discrete, ordered steps. This approach provides:

- **Pluggability**: Easy addition/removal of authentication steps
- **Orderability**: Configurable execution sequence with predefined priorities
- **Reusability**: Steps can be shared across different flow types
- **Testability**: Each component can be tested in isolation
- **Flexibility**: Support for different authentication methods and requirements

## Core Components

### 1. LoginFlowStep Interface

The foundation of the system. Every step must implement this interface:

```go
type LoginFlowStep interface {
    Name() string                                                    // Unique identifier
    Order() int                                                      // Execution priority (lower = earlier)
    Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error)  // Main logic
    ShouldSkip(ctx context.Context, flowContext *FlowContext) bool   // Conditional execution
}
```

### 2. FlowContext

Carries state and data between steps:

```go
type FlowContext struct {
    Request          Request                    // Input data (username, password, etc.)
    Result           *Result                    // Output data (tokens, user info, etc.)
    LoginID          uuid.UUID                  // Parsed login identifier
    Users            []mapper.User              // Associated user accounts
    DeviceRecognized bool                       // Device recognition status
    StepData         map[string]interface{}     // Inter-step data storage
    Services         *ServiceDependencies       // Injected services
}
```

### 3. StepResult

Defines the outcome of step execution:

```go
type StepResult struct {
    Continue    bool                        // Whether to proceed to next step
    EarlyReturn bool                        // Whether to return immediately
    Error       *Error                      // Step-specific error
    Data        map[string]interface{}      // Data to store in FlowContext
}
```

## Flow Architecture

### Step Registry

The `StepRegistry` manages and orders steps:

```go
registry := NewStepRegistry()
registry.AddStep(step1).AddStep(step2).AddStep(step3)

// Steps are automatically sorted by their Order() value
orderedSteps := registry.GetOrderedSteps()
```

### Flow Executor

The `FlowExecutor` orchestrates step execution:

```go
executor := NewFlowExecutor(registry, services)
result := executor.Execute(ctx, request)
```

**Execution Flow:**
1. Initialize `FlowContext` with request data and services
2. Get ordered steps from registry
3. For each step:
   - Check if step should be skipped (`ShouldSkip()`)
   - Execute step logic (`Execute()`)
   - Handle result (continue, early return, or error)
   - Store step data in context
4. Return final result

### Predefined Step Orders

The system defines standard execution priorities:

```go
const (
    OrderCredentialAuthentication = 100    // Validate credentials
    OrderUserValidation          = 200    // Ensure user exists
    OrderLoginIDParsing          = 300    // Parse login identifier
    OrderDeviceRecognition       = 400    // Check device status
    OrderTwoFARequirement        = 500    // Handle 2FA requirements
    OrderMultipleUsers           = 600    // Handle multiple user accounts
    OrderTokenGeneration         = 700    // Generate JWT tokens
    OrderSuccessRecording        = 800    // Record successful login
)
```

## Builder Pattern

### FlowBuilder

Provides a fluent interface for constructing flows:

```go
builder := NewFlowBuilder()
executor := builder.
    AddStep(NewCredentialAuthenticationStep("username")).
    AddStep(NewUserValidationStep()).
    AddStep(NewTokenGenerationStep("web")).
    Build(services)
```

### LoginFlowBuilders

Pre-configured builders for common flow types:

```go
builders := NewLoginFlowBuilders(
    loginService,
    twoFactorService,
    deviceService,
    tokenService,
    userMapper,
)

// Use pre-configured flows
webFlow := builders.BuildWebLoginFlow()
mobileFlow := builders.BuildMobileLoginFlow()
customFlow := builders.BuildCustomFlow(customSteps)
```

## Pre-configured Flows

### 1. Web Login Flow
**Steps:** Credential Auth → User Validation → Login ID Parsing → Device Recognition → 2FA → Multiple Users → Token Generation → Success Recording

**Use Case:** Standard web application login with full security features

### 2. Mobile Login Flow
**Steps:** Same as web flow but with mobile-specific token generation

**Use Case:** Mobile applications requiring device-specific tokens

### 3. Email Login Flow
**Steps:** Email-based credential authentication with standard flow

**Use Case:** Email/password authentication

### 4. Magic Link Flow
**Steps:** Magic link validation → User Validation → Login ID Parsing → Multiple Users → Token Generation → Success Recording

**Use Case:** Passwordless authentication via email links (skips device recognition and 2FA)

### 5. Minimal Flow
**Steps:** Credential Auth → User Validation → Login ID Parsing → Token Generation → Success Recording

**Use Case:** Simple authentication without advanced security features

### 6. Passwordless Flow
**Steps:** Credential Auth → User Validation → Login ID Parsing → Device Recognition → Multiple Users → Token Generation → Success Recording

**Use Case:** Passwordless authentication with device recognition (skips 2FA)

## Creating Custom Flows

### Method 1: Using FlowBuilder

```go
customFlow := NewFlowBuilder().
    AddStep(NewCredentialAuthenticationStep("username")).
    AddStep(NewUserValidationStep()).
    AddStep(NewCustomSecurityStep()).  // Your custom step
    AddStep(NewTokenGenerationStep("web")).
    Build(services)
```

### Method 2: Using LoginFlowBuilders

```go
customSteps := []LoginFlowStep{
    NewCredentialAuthenticationStep("email"),
    NewCustomValidationStep(),
    NewTokenGenerationStep("api"),
}

executor := builders.BuildCustomFlow(customSteps)
```

### Method 3: Dynamic Flow Selection

```go
flowType := FlowType("custom_flow")
executor := builders.BuildFlowByType(flowType)
```

## Step Implementation

### Creating a Custom Step

```go
type CustomValidationStep struct {
    config CustomConfig
}

func NewCustomValidationStep(config CustomConfig) *CustomValidationStep {
    return &CustomValidationStep{config: config}
}

func (s *CustomValidationStep) Name() string {
    return "custom_validation"
}

func (s *CustomValidationStep) Order() int {
    return 250  // Between user validation (200) and login ID parsing (300)
}

func (s *CustomValidationStep) ShouldSkip(ctx context.Context, flowContext *FlowContext) bool {
    // Skip if custom validation is disabled
    return !s.config.Enabled
}

func (s *CustomValidationStep) Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error) {
    // Perform custom validation logic
    if !s.validateCustomRules(flowContext.Result.Users) {
        return &StepResult{
            Error: &Error{
                Type:    "custom_validation_failed",
                Message: "Custom validation rules not met",
            },
        }, nil
    }

    // Store validation result
    return &StepResult{
        Continue: true,
        Data: map[string]interface{}{
            "custom_validation_passed": true,
            "validation_timestamp":     time.Now(),
        },
    }, nil
}

func (s *CustomValidationStep) validateCustomRules(users []mapper.User) bool {
    // Your custom validation logic here
    return true
}
```

## Usage Examples

### Basic Usage

```go
// Initialize services
services := &ServiceDependencies{
    LoginService:     loginSvc,
    TwoFactorService: twoFASvc,
    DeviceService:    deviceSvc,
    TokenService:     tokenSvc,
    UserMapper:       userMapper,
}

// Create flow builders
builders := NewLoginFlowBuilders(
    services.LoginService,
    services.TwoFactorService,
    services.DeviceService,
    services.TokenService,
    services.UserMapper,
)

// Execute web login flow
request := Request{
    Username:          "user@example.com",
    Password:          "password123",
    IPAddress:         "192.168.1.1",
    UserAgent:         "Mozilla/5.0...",
    DeviceFingerprint: "device123",
}

executor := builders.BuildWebLoginFlow()
result := executor.Execute(ctx, request)

if result.ErrorResponse != nil {
    // Handle error
    log.Printf("Login failed: %s", result.ErrorResponse.Message)
} else if result.RequiresTwoFA {
    // Handle 2FA requirement
    log.Printf("2FA required, temp token: %s", result.Tokens["temp_token"].Token)
} else if result.Success {
    // Handle successful login
    log.Printf("Login successful, access token: %s", result.Tokens["access_token"].Token)
}
```

### Advanced Custom Flow

```go
// Create a custom enterprise flow
enterpriseFlow := NewFlowBuilder().
    AddStep(NewCredentialAuthenticationStep("username")).
    AddStep(NewUserValidationStep()).
    AddStep(NewLoginIDParsingStep()).
    AddStep(NewEnterpriseSecurityStep()).      // Custom step
    AddStep(NewComplianceCheckStep()).         // Custom step
    AddStep(NewDeviceRecognitionStep()).
    AddStep(NewTwoFARequirementStep()).
    AddStep(NewAuditLoggingStep()).           // Custom step
    AddStep(NewTokenGenerationStep("enterprise")).
    AddStep(NewSuccessRecordingStep()).
    Build(services)

result := enterpriseFlow.Execute(ctx, request)
```

### Conditional Flow Building

```go
func buildFlowForUser(userType string, services *ServiceDependencies) *FlowExecutor {
    builder := NewFlowBuilder().
        AddStep(NewCredentialAuthenticationStep("username")).
        AddStep(NewUserValidationStep()).
        AddStep(NewLoginIDParsingStep())

    // Add steps based on user type
    switch userType {
    case "admin":
        builder.AddStep(NewAdminValidationStep()).
                AddStep(NewTwoFARequirementStep())
    case "enterprise":
        builder.AddStep(NewEnterpriseSecurityStep()).
                AddStep(NewComplianceCheckStep())
    }

    return builder.
        AddStep(NewTokenGenerationStep("web")).
        AddStep(NewSuccessRecordingStep()).
        Build(services)
}
```

## Testing

The architecture supports comprehensive testing at multiple levels:

### Unit Testing Steps

```go
func TestCustomValidationStep(t *testing.T) {
    step := NewCustomValidationStep(CustomConfig{Enabled: true})
    
    flowContext := &FlowContext{
        Result: &Result{
            Users: []mapper.User{{UserId: "user123"}},
        },
        StepData: make(map[string]interface{}),
    }

    result, err := step.Execute(context.Background(), flowContext)
    
    assert.NoError(t, err)
    assert.True(t, result.Continue)
    assert.True(t, result.Data["custom_validation_passed"].(bool))
}
```

### Integration Testing Flows

```go
func TestWebLoginFlow(t *testing.T) {
    // Setup mock services
    services := setupMockServices()
    
    builders := NewLoginFlowBuilders(/* services */)
    executor := builders.BuildWebLoginFlow()
    
    request := Request{
        Username: "testuser",
        Password: "password",
    }
    
    result := executor.Execute(context.Background(), request)
    
    assert.Nil(t, result.ErrorResponse)
    assert.True(t, result.Success)
}
```

### Testing Flow Composition

```go
func TestFlowStepOrdering(t *testing.T) {
    builder := NewFlowBuilder().
        AddStep(NewMockStep("step3", 300)).
        AddStep(NewMockStep("step1", 100)).
        AddStep(NewMockStep("step2", 200))
    
    executor := builder.Build(services)
    steps := executor.registry.GetOrderedSteps()
    
    assert.Equal(t, "step1", steps[0].Name())
    assert.Equal(t, "step2", steps[1].Name())
    assert.Equal(t, "step3", steps[2].Name())
}
```

## Best Practices

1. **Step Naming**: Use descriptive, consistent names for steps
2. **Order Values**: Leave gaps between order values (100, 200, 300) for future insertions
3. **Error Handling**: Always return structured errors with meaningful messages
4. **Data Storage**: Use the StepData map for sharing information between steps
5. **Skip Logic**: Implement ShouldSkip() for conditional step execution
6. **Testing**: Write unit tests for individual steps and integration tests for complete flows
7. **Documentation**: Document custom steps and their purpose
8. **Service Injection**: Use the ServiceDependencies pattern for accessing external services

This architecture provides a robust foundation for building flexible, maintainable authentication flows that can adapt to changing requirements while maintaining clean separation of concerns.
