package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// ChallengeMethod represents the PKCE challenge method
type ChallengeMethod string

const (
	// ChallengePlain represents the "plain" challenge method (not recommended for production)
	ChallengePlain ChallengeMethod = "plain"
	// ChallengeS256 represents the "S256" challenge method (recommended)
	ChallengeS256 ChallengeMethod = "S256"
)

// CodeVerifier represents a PKCE code verifier
type CodeVerifier struct {
	Value string
}

// CodeChallenge represents a PKCE code challenge
type CodeChallenge struct {
	Value  string
	Method ChallengeMethod
}

// GenerateCodeVerifier generates a cryptographically random code verifier
// The code verifier should be a cryptographically random string using the characters
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a minimum length of 43 characters
// and a maximum length of 128 characters.
func GenerateCodeVerifier() (*CodeVerifier, error) {
	// Generate 32 random bytes (will result in 43 characters when base64url encoded)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64url encode without padding
	verifier := base64.RawURLEncoding.EncodeToString(bytes)

	return &CodeVerifier{Value: verifier}, nil
}

// GenerateCodeChallenge generates a code challenge from the code verifier using the specified method
func (cv *CodeVerifier) GenerateCodeChallenge(method ChallengeMethod) (*CodeChallenge, error) {
	switch method {
	case ChallengePlain:
		return &CodeChallenge{
			Value:  cv.Value,
			Method: ChallengePlain,
		}, nil
	case ChallengeS256:
		hash := sha256.Sum256([]byte(cv.Value))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return &CodeChallenge{
			Value:  challenge,
			Method: ChallengeS256,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported challenge method: %s", method)
	}
}

// ValidateCodeVerifier validates that a code verifier matches the given code challenge
func ValidateCodeVerifier(verifier string, challenge string, method ChallengeMethod) error {
	if verifier == "" {
		return fmt.Errorf("code verifier cannot be empty")
	}

	if challenge == "" {
		return fmt.Errorf("code challenge cannot be empty")
	}

	// Validate verifier length (43-128 characters)
	if len(verifier) < 43 || len(verifier) > 128 {
		return fmt.Errorf("code verifier must be between 43 and 128 characters")
	}

	// Validate verifier characters
	if !isValidCodeVerifier(verifier) {
		return fmt.Errorf("code verifier contains invalid characters")
	}

	switch method {
	case ChallengePlain:
		if verifier != challenge {
			return fmt.Errorf("code verifier does not match challenge")
		}
	case ChallengeS256:
		hash := sha256.Sum256([]byte(verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if expectedChallenge != challenge {
			return fmt.Errorf("code verifier does not match challenge")
		}
	default:
		return fmt.Errorf("unsupported challenge method: %s", method)
	}

	return nil
}

// IsValidChallengeMethod checks if the given challenge method is valid
func IsValidChallengeMethod(method string) bool {
	return method == string(ChallengePlain) || method == string(ChallengeS256)
}

// isValidCodeVerifier checks if the code verifier contains only allowed characters
func isValidCodeVerifier(verifier string) bool {
	allowedChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for _, char := range verifier {
		if !strings.ContainsRune(allowedChars, char) {
			return false
		}
	}
	return true
}

// PKCEParams represents the PKCE parameters for an authorization request
type PKCEParams struct {
	CodeChallenge       string
	CodeChallengeMethod ChallengeMethod
}

// NewPKCEParams creates new PKCE parameters with the given challenge and method
func NewPKCEParams(challenge string, method string) (*PKCEParams, error) {
	if challenge == "" {
		return nil, fmt.Errorf("code challenge cannot be empty")
	}

	if !IsValidChallengeMethod(method) {
		return nil, fmt.Errorf("invalid challenge method: %s", method)
	}

	return &PKCEParams{
		CodeChallenge:       challenge,
		CodeChallengeMethod: ChallengeMethod(method),
	}, nil
}

// Validate validates the PKCE parameters
func (p *PKCEParams) Validate() error {
	if p.CodeChallenge == "" {
		return fmt.Errorf("code challenge cannot be empty")
	}

	if !IsValidChallengeMethod(string(p.CodeChallengeMethod)) {
		return fmt.Errorf("invalid challenge method: %s", p.CodeChallengeMethod)
	}

	return nil
}
