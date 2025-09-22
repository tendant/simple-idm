package pkce

import (
	"strings"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() failed: %v", err)
	}

	if verifier == nil {
		t.Fatal("GenerateCodeVerifier() returned nil verifier")
	}

	if len(verifier.Value) < 43 {
		t.Errorf("Code verifier too short: got %d characters, want at least 43", len(verifier.Value))
	}

	if len(verifier.Value) > 128 {
		t.Errorf("Code verifier too long: got %d characters, want at most 128", len(verifier.Value))
	}

	// Test that verifier contains only valid characters
	if !isValidCodeVerifier(verifier.Value) {
		t.Errorf("Code verifier contains invalid characters: %s", verifier.Value)
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() failed: %v", err)
	}

	tests := []struct {
		name   string
		method ChallengeMethod
	}{
		{"Plain method", ChallengePlain},
		{"S256 method", ChallengeS256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, err := verifier.GenerateCodeChallenge(tt.method)
			if err != nil {
				t.Fatalf("GenerateCodeChallenge() failed: %v", err)
			}

			if challenge == nil {
				t.Fatal("GenerateCodeChallenge() returned nil challenge")
			}

			if challenge.Method != tt.method {
				t.Errorf("Challenge method mismatch: got %s, want %s", challenge.Method, tt.method)
			}

			if challenge.Value == "" {
				t.Error("Challenge value is empty")
			}

			// For plain method, challenge should equal verifier
			if tt.method == ChallengePlain && challenge.Value != verifier.Value {
				t.Error("Plain challenge should equal verifier value")
			}

			// For S256 method, challenge should be different from verifier
			if tt.method == ChallengeS256 && challenge.Value == verifier.Value {
				t.Error("S256 challenge should be different from verifier value")
			}
		})
	}
}

func TestGenerateCodeChallengeInvalidMethod(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() failed: %v", err)
	}

	_, err = verifier.GenerateCodeChallenge("invalid")
	if err == nil {
		t.Error("GenerateCodeChallenge() should fail with invalid method")
	}
}

func TestValidateCodeVerifier(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() failed: %v", err)
	}

	// Test S256 method
	challenge, err := verifier.GenerateCodeChallenge(ChallengeS256)
	if err != nil {
		t.Fatalf("GenerateCodeChallenge() failed: %v", err)
	}

	err = ValidateCodeVerifier(verifier.Value, challenge.Value, ChallengeS256)
	if err != nil {
		t.Errorf("ValidateCodeVerifier() failed for valid S256: %v", err)
	}

	// Test plain method
	plainChallenge, err := verifier.GenerateCodeChallenge(ChallengePlain)
	if err != nil {
		t.Fatalf("GenerateCodeChallenge() failed: %v", err)
	}

	err = ValidateCodeVerifier(verifier.Value, plainChallenge.Value, ChallengePlain)
	if err != nil {
		t.Errorf("ValidateCodeVerifier() failed for valid plain: %v", err)
	}
}

func TestValidateCodeVerifierErrors(t *testing.T) {
	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    ChallengeMethod
		wantError bool
	}{
		{
			name:      "Empty verifier",
			verifier:  "",
			challenge: "challenge",
			method:    ChallengeS256,
			wantError: true,
		},
		{
			name:      "Empty challenge",
			verifier:  "verifier",
			challenge: "",
			method:    ChallengeS256,
			wantError: true,
		},
		{
			name:      "Verifier too short",
			verifier:  "short",
			challenge: "challenge",
			method:    ChallengeS256,
			wantError: true,
		},
		{
			name:      "Verifier too long",
			verifier:  strings.Repeat("a", 129),
			challenge: "challenge",
			method:    ChallengeS256,
			wantError: true,
		},
		{
			name:      "Invalid verifier characters",
			verifier:  strings.Repeat("!", 43),
			challenge: "challenge",
			method:    ChallengeS256,
			wantError: true,
		},
		{
			name:      "Invalid method",
			verifier:  strings.Repeat("a", 43),
			challenge: "challenge",
			method:    "invalid",
			wantError: true,
		},
		{
			name:      "Plain method mismatch",
			verifier:  strings.Repeat("a", 43),
			challenge: "different",
			method:    ChallengePlain,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCodeVerifier(tt.verifier, tt.challenge, tt.method)
			if tt.wantError && err == nil {
				t.Error("ValidateCodeVerifier() should have returned an error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("ValidateCodeVerifier() unexpected error: %v", err)
			}
		})
	}
}

func TestIsValidChallengeMethod(t *testing.T) {
	tests := []struct {
		method string
		valid  bool
	}{
		{"plain", true},
		{"S256", true},
		{"invalid", false},
		{"", false},
		{"PLAIN", false}, // case sensitive
		{"s256", false},  // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := IsValidChallengeMethod(tt.method)
			if result != tt.valid {
				t.Errorf("IsValidChallengeMethod(%s) = %v, want %v", tt.method, result, tt.valid)
			}
		})
	}
}

func TestNewPKCEParams(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    string
		wantError bool
	}{
		{
			name:      "Valid S256",
			challenge: "challenge",
			method:    "S256",
			wantError: false,
		},
		{
			name:      "Valid plain",
			challenge: "challenge",
			method:    "plain",
			wantError: false,
		},
		{
			name:      "Empty challenge",
			challenge: "",
			method:    "S256",
			wantError: true,
		},
		{
			name:      "Invalid method",
			challenge: "challenge",
			method:    "invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := NewPKCEParams(tt.challenge, tt.method)
			if tt.wantError {
				if err == nil {
					t.Error("NewPKCEParams() should have returned an error")
				}
				return
			}

			if err != nil {
				t.Errorf("NewPKCEParams() unexpected error: %v", err)
				return
			}

			if params.CodeChallenge != tt.challenge {
				t.Errorf("CodeChallenge = %s, want %s", params.CodeChallenge, tt.challenge)
			}

			if string(params.CodeChallengeMethod) != tt.method {
				t.Errorf("CodeChallengeMethod = %s, want %s", params.CodeChallengeMethod, tt.method)
			}
		})
	}
}

func TestPKCEParamsValidate(t *testing.T) {
	tests := []struct {
		name   string
		params *PKCEParams
		valid  bool
	}{
		{
			name: "Valid S256",
			params: &PKCEParams{
				CodeChallenge:       "challenge",
				CodeChallengeMethod: ChallengeS256,
			},
			valid: true,
		},
		{
			name: "Valid plain",
			params: &PKCEParams{
				CodeChallenge:       "challenge",
				CodeChallengeMethod: ChallengePlain,
			},
			valid: true,
		},
		{
			name: "Empty challenge",
			params: &PKCEParams{
				CodeChallenge:       "",
				CodeChallengeMethod: ChallengeS256,
			},
			valid: false,
		},
		{
			name: "Invalid method",
			params: &PKCEParams{
				CodeChallenge:       "challenge",
				CodeChallengeMethod: "invalid",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.valid && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("Validate() should have returned an error")
			}
		})
	}
}

func TestIsValidCodeVerifier(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
		valid    bool
	}{
		{
			name:     "Valid characters",
			verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
			valid:    true,
		},
		{
			name:     "Invalid character !",
			verifier: "abc!def",
			valid:    false,
		},
		{
			name:     "Invalid character @",
			verifier: "abc@def",
			valid:    false,
		},
		{
			name:     "Invalid character space",
			verifier: "abc def",
			valid:    false,
		},
		{
			name:     "Empty string",
			verifier: "",
			valid:    true, // empty string has no invalid characters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidCodeVerifier(tt.verifier)
			if result != tt.valid {
				t.Errorf("isValidCodeVerifier(%s) = %v, want %v", tt.verifier, result, tt.valid)
			}
		})
	}
}

// TestPKCEFlow tests the complete PKCE flow
func TestPKCEFlow(t *testing.T) {
	// Generate code verifier
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() failed: %v", err)
	}

	// Generate code challenge
	challenge, err := verifier.GenerateCodeChallenge(ChallengeS256)
	if err != nil {
		t.Fatalf("GenerateCodeChallenge() failed: %v", err)
	}

	// Create PKCE params
	params, err := NewPKCEParams(challenge.Value, string(challenge.Method))
	if err != nil {
		t.Fatalf("NewPKCEParams() failed: %v", err)
	}

	// Validate params
	err = params.Validate()
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	// Validate code verifier against challenge
	err = ValidateCodeVerifier(verifier.Value, challenge.Value, challenge.Method)
	if err != nil {
		t.Fatalf("ValidateCodeVerifier() failed: %v", err)
	}
}
