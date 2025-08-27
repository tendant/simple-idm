package loginflow

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/device"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
)

// LoginFlowStep represents a single step in the login flow
type LoginFlowStep interface {
	// Name returns the unique name of this step
	Name() string

	// Order returns the execution order (lower numbers execute first)
	Order() int

	// Execute performs the step's logic
	Execute(ctx context.Context, flowContext *FlowContext) (*StepResult, error)

	// ShouldSkip determines if this step should be skipped based on current context
	ShouldSkip(ctx context.Context, flowContext *FlowContext) bool
}

// FlowContext carries state between login flow steps
type FlowContext struct {
	// Input data
	Request Request

	// Current state
	Result           *Result
	LoginID          uuid.UUID
	Users            []mapper.User
	DeviceRecognized bool

	// Step-specific data (can be used by steps to store intermediate results)
	StepData map[string]interface{}

	// Services (injected by the flow executor)
	Services *ServiceDependencies
}

// StepResult represents the result of executing a login flow step
type StepResult struct {
	// Continue indicates whether the flow should continue to the next step
	Continue bool

	// EarlyReturn indicates the flow should return immediately with the current result
	EarlyReturn bool

	// Error indicates an error occurred during step execution
	Error *Error

	// Data can contain step-specific data to be stored in FlowContext.StepData
	Data map[string]interface{}
}

// ServiceDependencies contains all the services needed by login flow steps
type ServiceDependencies struct {
	LoginService     *login.LoginService
	TwoFactorService twofa.TwoFactorService
	DeviceService    *device.DeviceService
	TokenService     tg.TokenService
	UserMapper       mapper.UserMapper
}

// StepRegistry manages and orders login flow steps
type StepRegistry struct {
	steps []LoginFlowStep
}

// NewStepRegistry creates a new step registry
func NewStepRegistry() *StepRegistry {
	return &StepRegistry{
		steps: make([]LoginFlowStep, 0),
	}
}

// AddStep adds a step to the registry
func (r *StepRegistry) AddStep(step LoginFlowStep) *StepRegistry {
	r.steps = append(r.steps, step)
	return r
}

// GetOrderedSteps returns steps sorted by their order
func (r *StepRegistry) GetOrderedSteps() []LoginFlowStep {
	// Create a copy to avoid modifying the original slice
	orderedSteps := make([]LoginFlowStep, len(r.steps))
	copy(orderedSteps, r.steps)

	// Sort by order
	sort.Slice(orderedSteps, func(i, j int) bool {
		return orderedSteps[i].Order() < orderedSteps[j].Order()
	})

	return orderedSteps
}

// FlowExecutor orchestrates the execution of login flow steps
type FlowExecutor struct {
	registry *StepRegistry
	services *ServiceDependencies
}

// NewFlowExecutor creates a new flow executor
func NewFlowExecutor(registry *StepRegistry, services *ServiceDependencies) *FlowExecutor {
	return &FlowExecutor{
		registry: registry,
		services: services,
	}
}

// Execute runs the complete login flow
func (e *FlowExecutor) Execute(ctx context.Context, request Request) Result {
	// Initialize flow context
	flowContext := &FlowContext{
		Request:  request,
		Result:   &Result{},
		StepData: make(map[string]interface{}),
		Services: e.services,
	}

	// Get ordered steps
	steps := e.registry.GetOrderedSteps()

	// Execute each step
	for _, step := range steps {
		// Check if step should be skipped
		if step.ShouldSkip(ctx, flowContext) {
			continue
		}

		// Execute the step
		stepResult, err := step.Execute(ctx, flowContext)
		if err != nil {
			// If step execution fails, return error
			flowContext.Result.ErrorResponse = &Error{
				Type:    "step_execution_error",
				Message: fmt.Sprintf("Step '%s' failed: %v", step.Name(), err),
			}
			return *flowContext.Result
		}

		// Handle step result
		if stepResult.Error != nil {
			flowContext.Result.ErrorResponse = stepResult.Error
			return *flowContext.Result
		}

		// Store step data
		if stepResult.Data != nil {
			for key, value := range stepResult.Data {
				flowContext.StepData[key] = value
			}
		}

		// Check for early return
		if stepResult.EarlyReturn {
			return *flowContext.Result
		}

		// Check if flow should continue
		if !stepResult.Continue {
			break
		}
	}

	return *flowContext.Result
}

// FlowBuilder provides a fluent interface for building login flows
type FlowBuilder struct {
	registry *StepRegistry
}

// NewFlowBuilder creates a new flow builder
func NewFlowBuilder() *FlowBuilder {
	return &FlowBuilder{
		registry: NewStepRegistry(),
	}
}

// AddStep adds a step to the flow
func (b *FlowBuilder) AddStep(step LoginFlowStep) *FlowBuilder {
	b.registry.AddStep(step)
	return b
}

// Build creates a flow executor with the configured steps
func (b *FlowBuilder) Build(services *ServiceDependencies) *FlowExecutor {
	return NewFlowExecutor(b.registry, services)
}

// Predefined step orders (can be used by concrete step implementations)
const (
	OrderCredentialAuthentication = 100
	OrderUserValidation           = 200
	OrderLoginIDParsing           = 300
	OrderDeviceRecognition        = 400
	OrderTwoFARequirement         = 500
	OrderMultipleUsers            = 600
	OrderTokenGeneration          = 700
	OrderSuccessRecording         = 800
)
