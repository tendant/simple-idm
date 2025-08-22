package tokengenerator

import (
	"testing"
	"time"
)

func TestParseDurationValue(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    time.Duration
		wantErr bool
	}{
		{
			name:    "valid time.Duration",
			input:   5 * time.Minute,
			want:    5 * time.Minute,
			wantErr: false,
		},
		{
			name:    "valid string duration - minutes",
			input:   "10m",
			want:    10 * time.Minute,
			wantErr: false,
		},
		{
			name:    "valid string duration - hours",
			input:   "2h",
			want:    2 * time.Hour,
			wantErr: false,
		},
		{
			name:    "valid string duration - complex",
			input:   "1h30m",
			want:    90 * time.Minute,
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: false,
		},
		{
			name:    "invalid string duration",
			input:   "invalid",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid type - int",
			input:   123,
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid type - nil",
			input:   nil,
			want:    0,
			wantErr: true,
		},
		{
			name:    "negative duration",
			input:   "-5s",
			want:    -5 * time.Second,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDurationValue(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDurationValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDurationValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDefaultTokenServiceWithOptions(t *testing.T) {
	// Create test generators
	tokenGen := NewJwtTokenGenerator("test-secret", "test-issuer", "test-audience")
	tempTokenGen := NewTempTokenGenerator("test-secret", "test-issuer", "test-audience")

	tests := []struct {
		name                     string
		options                  []Option
		expectedAccessExpiry     time.Duration
		expectedRefreshExpiry    time.Duration
		expectedTempExpiry       time.Duration
		expectedLogoutExpiry     time.Duration
		expectedMobileExpiry     time.Duration
	}{
		{
			name:                     "no options - use defaults",
			options:                  []Option{},
			expectedAccessExpiry:     DefaultAccessTokenExpiry,
			expectedRefreshExpiry:    DefaultRefreshTokenExpiry,
			expectedTempExpiry:       DefaultTempTokenExpiry,
			expectedLogoutExpiry:     DefaultLogoutTokenExpiry,
			expectedMobileExpiry:     DefaultMobileRefreshTokenExpiry,
		},
		{
			name: "string durations",
			options: []Option{
				WithAccessTokenExpiry("1h"),
				WithRefreshTokenExpiry("24h"),
				WithTempTokenExpiry("30m"),
				WithLogoutTokenExpiry("-2s"),
			},
			expectedAccessExpiry:     1 * time.Hour,
			expectedRefreshExpiry:    24 * time.Hour,
			expectedTempExpiry:       30 * time.Minute,
			expectedLogoutExpiry:     -2 * time.Second,
			expectedMobileExpiry:     DefaultMobileRefreshTokenExpiry,
		},
		{
			name: "time.Duration values",
			options: []Option{
				WithAccessTokenExpiry(2 * time.Hour),
				WithRefreshTokenExpiry(48 * time.Hour),
				WithTempTokenExpiry(15 * time.Minute),
				WithLogoutTokenExpiry(-1 * time.Second),
				WithMobileRefreshTokenExpiry(30 * 24 * time.Hour),
			},
			expectedAccessExpiry:     2 * time.Hour,
			expectedRefreshExpiry:    48 * time.Hour,
			expectedTempExpiry:       15 * time.Minute,
			expectedLogoutExpiry:     -1 * time.Second,
			expectedMobileExpiry:     30 * 24 * time.Hour,
		},
		{
			name: "mixed string and duration",
			options: []Option{
				WithAccessTokenExpiry("30m"),
				WithRefreshTokenExpiry(12 * time.Hour),
				WithTempTokenExpiry("5m"),
				WithLogoutTokenExpiry(0 * time.Second),
			},
			expectedAccessExpiry:     30 * time.Minute,
			expectedRefreshExpiry:    12 * time.Hour,
			expectedTempExpiry:       5 * time.Minute,
			expectedLogoutExpiry:     0,
			expectedMobileExpiry:     DefaultMobileRefreshTokenExpiry,
		},
		{
			name: "invalid values - use defaults",
			options: []Option{
				WithAccessTokenExpiry("invalid"),
				WithRefreshTokenExpiry(123), // wrong type
				WithTempTokenExpiry(""),     // empty string
			},
			expectedAccessExpiry:     DefaultAccessTokenExpiry,
			expectedRefreshExpiry:    DefaultRefreshTokenExpiry,
			expectedTempExpiry:       DefaultTempTokenExpiry,
			expectedLogoutExpiry:     DefaultLogoutTokenExpiry,
			expectedMobileExpiry:     DefaultMobileRefreshTokenExpiry,
		},
		{
			name: "zero duration for logout token",
			options: []Option{
				WithLogoutTokenExpiry("0s"),
			},
			expectedAccessExpiry:     DefaultAccessTokenExpiry,
			expectedRefreshExpiry:    DefaultRefreshTokenExpiry,
			expectedTempExpiry:       DefaultTempTokenExpiry,
			expectedLogoutExpiry:     0,
			expectedMobileExpiry:     DefaultMobileRefreshTokenExpiry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewDefaultTokenServiceWithOptions(
				tokenGen,
				tokenGen,
				tempTokenGen,
				tokenGen,
				"test-secret",
				tt.options...,
			).(*DefaultTokenService)

			if service.accessTokenExpiry != tt.expectedAccessExpiry {
				t.Errorf("accessTokenExpiry = %v, want %v", service.accessTokenExpiry, tt.expectedAccessExpiry)
			}
			if service.refreshTokenExpiry != tt.expectedRefreshExpiry {
				t.Errorf("refreshTokenExpiry = %v, want %v", service.refreshTokenExpiry, tt.expectedRefreshExpiry)
			}
			if service.tempTokenExpiry != tt.expectedTempExpiry {
				t.Errorf("tempTokenExpiry = %v, want %v", service.tempTokenExpiry, tt.expectedTempExpiry)
			}
			if service.logoutTokenExpiry != tt.expectedLogoutExpiry {
				t.Errorf("logoutTokenExpiry = %v, want %v", service.logoutTokenExpiry, tt.expectedLogoutExpiry)
			}
			if service.mobileRefreshTokenExpiry != tt.expectedMobileExpiry {
				t.Errorf("mobileRefreshTokenExpiry = %v, want %v", service.mobileRefreshTokenExpiry, tt.expectedMobileExpiry)
			}
		})
	}
}

func TestTokenGenerationWithOptions(t *testing.T) {
	// Create test generators
	tokenGen := NewJwtTokenGenerator("test-secret", "test-issuer", "test-audience")
	tempTokenGen := NewTempTokenGenerator("test-secret", "test-issuer", "test-audience")

	// Create service with custom expiry times
	service := NewDefaultTokenServiceWithOptions(
		tokenGen,
		tokenGen,
		tempTokenGen,
		tokenGen,
		"test-secret",
		WithAccessTokenExpiry("2h"),
		WithRefreshTokenExpiry("48h"),
		WithTempTokenExpiry("20m"),
		WithLogoutTokenExpiry("-5s"),
	)

	// Test token generation
	t.Run("GenerateTokens", func(t *testing.T) {
		tokens, err := service.GenerateTokens("test-subject", nil, map[string]interface{}{"test": "claim"})
		if err != nil {
			t.Fatalf("GenerateTokens() error = %v", err)
		}

		// Check that tokens are generated
		if _, ok := tokens[ACCESS_TOKEN_NAME]; !ok {
			t.Error("Access token not generated")
		}
		if _, ok := tokens[REFRESH_TOKEN_NAME]; !ok {
			t.Error("Refresh token not generated")
		}

		// Verify expiry times are in the expected range
		accessToken := tokens[ACCESS_TOKEN_NAME]
		expectedAccessExpiry := time.Now().Add(2 * time.Hour)
		if diff := accessToken.Expiry.Sub(expectedAccessExpiry).Abs(); diff > 1*time.Minute {
			t.Errorf("Access token expiry off by %v", diff)
		}

		refreshToken := tokens[REFRESH_TOKEN_NAME]
		expectedRefreshExpiry := time.Now().Add(48 * time.Hour)
		if diff := refreshToken.Expiry.Sub(expectedRefreshExpiry).Abs(); diff > 1*time.Minute {
			t.Errorf("Refresh token expiry off by %v", diff)
		}
	})

	t.Run("GenerateTempToken", func(t *testing.T) {
		tokens, err := service.GenerateTempToken("test-subject", nil, map[string]interface{}{
			"login_id": "123",
		})
		if err != nil {
			t.Fatalf("GenerateTempToken() error = %v", err)
		}

		tempToken, ok := tokens[TEMP_TOKEN_NAME]
		if !ok {
			t.Fatal("Temp token not generated")
		}

		expectedTempExpiry := time.Now().Add(20 * time.Minute)
		if diff := tempToken.Expiry.Sub(expectedTempExpiry).Abs(); diff > 1*time.Minute {
			t.Errorf("Temp token expiry off by %v", diff)
		}
	})
}

func TestOptionFunctions(t *testing.T) {
	t.Run("WithAccessTokenExpiry", func(t *testing.T) {
		service := &DefaultTokenService{
			accessTokenExpiry: DefaultAccessTokenExpiry,
		}

		// Test with string
		WithAccessTokenExpiry("3h")(service)
		if service.accessTokenExpiry != 3*time.Hour {
			t.Errorf("Expected 3h, got %v", service.accessTokenExpiry)
		}

		// Test with duration
		WithAccessTokenExpiry(4 * time.Hour)(service)
		if service.accessTokenExpiry != 4*time.Hour {
			t.Errorf("Expected 4h, got %v", service.accessTokenExpiry)
		}

		// Test with invalid string (should not change)
		WithAccessTokenExpiry("invalid")(service)
		if service.accessTokenExpiry != 4*time.Hour {
			t.Errorf("Expected 4h (unchanged), got %v", service.accessTokenExpiry)
		}

		// Test with zero duration (should not change)
		WithAccessTokenExpiry(0 * time.Second)(service)
		if service.accessTokenExpiry != 4*time.Hour {
			t.Errorf("Expected 4h (unchanged), got %v", service.accessTokenExpiry)
		}
	})

	t.Run("WithLogoutTokenExpiry allows zero and negative", func(t *testing.T) {
		service := &DefaultTokenService{
			logoutTokenExpiry: DefaultLogoutTokenExpiry,
		}

		// Test with zero
		WithLogoutTokenExpiry("0s")(service)
		if service.logoutTokenExpiry != 0 {
			t.Errorf("Expected 0, got %v", service.logoutTokenExpiry)
		}

		// Test with negative
		WithLogoutTokenExpiry(-10 * time.Second)(service)
		if service.logoutTokenExpiry != -10*time.Second {
			t.Errorf("Expected -10s, got %v", service.logoutTokenExpiry)
		}
	})
}