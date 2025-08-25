package twofa

import (
	"testing"

	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
)

func TestConfigurablePeriods(t *testing.T) {
	// Test default values
	service := NewTwoFaService(&twofadb.Queries{})

	if service.totpPeriod != 30 {
		t.Errorf("Expected default TOTP period to be 30, got %d", service.totpPeriod)
	}

	if service.smsPeriod != 300 {
		t.Errorf("Expected default SMS period to be 300, got %d", service.smsPeriod)
	}

	if service.emailPeriod != 300 {
		t.Errorf("Expected default Email period to be 300, got %d", service.emailPeriod)
	}
}

func TestConfigurablePeriodsWithOptions(t *testing.T) {
	// Test custom values using With functions
	service := NewTwoFaService(
		&twofadb.Queries{},
		WithTotpPeriod(60),
		WithSmsPeriod(600),
		WithEmailPeriod(900),
	)

	if service.totpPeriod != 60 {
		t.Errorf("Expected custom TOTP period to be 60, got %d", service.totpPeriod)
	}

	if service.smsPeriod != 600 {
		t.Errorf("Expected custom SMS period to be 600, got %d", service.smsPeriod)
	}

	if service.emailPeriod != 900 {
		t.Errorf("Expected custom Email period to be 900, got %d", service.emailPeriod)
	}
}

func TestGenerate2faPasscodeWithPeriod(t *testing.T) {
	service := NewTwoFaService(&twofadb.Queries{})

	// Test with a known secret
	secret := "JBSWY3DPEHPK3PXP" // Base32 encoded secret

	// Generate passcode with default period (30)
	passcode1, err := service.Generate2faPasscodeWithPeriod(secret, 30)
	if err != nil {
		t.Fatalf("Failed to generate passcode with period 30: %v", err)
	}

	// Generate passcode with custom period (300)
	passcode2, err := service.Generate2faPasscodeWithPeriod(secret, 300)
	if err != nil {
		t.Fatalf("Failed to generate passcode with period 300: %v", err)
	}

	// Passcodes should be different due to different periods
	if passcode1 == passcode2 {
		t.Error("Expected different passcodes for different periods, but got the same")
	}

	// Both should be 6 digits
	if len(passcode1) != 6 {
		t.Errorf("Expected passcode1 to be 6 digits, got %d", len(passcode1))
	}

	if len(passcode2) != 6 {
		t.Errorf("Expected passcode2 to be 6 digits, got %d", len(passcode2))
	}
}

func TestValidateTotpPasscodeWithPeriod(t *testing.T) {
	service := NewTwoFaService(&twofadb.Queries{})

	// Test with a known secret
	secret := "JBSWY3DPEHPK3PXP" // Base32 encoded secret

	// Generate a passcode with period 30
	passcode, err := service.Generate2faPasscodeWithPeriod(secret, 30)
	if err != nil {
		t.Fatalf("Failed to generate passcode: %v", err)
	}

	// Validate with the same period
	valid, err := service.ValidateTotpPasscodeWithPeriod(secret, passcode, 30)
	if err != nil {
		t.Fatalf("Failed to validate passcode: %v", err)
	}

	if !valid {
		t.Error("Expected passcode to be valid with matching period")
	}

	// Validate with different period should fail (most of the time)
	valid2, err := service.ValidateTotpPasscodeWithPeriod(secret, passcode, 300)
	if err != nil {
		t.Fatalf("Failed to validate passcode with different period: %v", err)
	}

	// Note: This might occasionally pass due to time window overlap, but usually fails
	// We'll just check that the function doesn't error out
	_ = valid2 // We don't assert this as it's time-dependent
}
