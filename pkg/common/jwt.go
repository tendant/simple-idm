package common

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// GetLoginIDFromClaims extracts the login ID from JWT claims
func GetLoginIDFromClaims(claims jwt.Claims) (string, error) {
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return "", fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("extra_claims has invalid format")
	}

	// Look for login_id in extra claims
	loginIDValue, ok := extraClaims["login_id"]
	if !ok {
		return "", fmt.Errorf("login_id not found in token claims")
	}

	loginIDStr, ok := loginIDValue.(string)
	if !ok || loginIDStr == "" {
		return "", fmt.Errorf("login_id is not a valid string")
	}

	return loginIDStr, nil
}

// GetUserIDFromClaims extracts the user ID from JWT claims
func GetUserIDFromClaims(claims jwt.Claims) (string, error) {
	// First try to get from subject
	subject, err := claims.GetSubject()
	if err == nil && subject != "" {
		return subject, nil
	}

	// If subject is empty or not available, try to get from extra claims
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return "", fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("extra_claims has invalid format")
	}

	// Try user_id first, then fall back to other common ID field names
	for _, field := range []string{"user_id", "user_uuid", "userId", "id", "sub"} {
		if idValue, ok := extraClaims[field]; ok {
			if idStr, ok := idValue.(string); ok && idStr != "" {
				return idStr, nil
			}
		}
	}

	return "", fmt.Errorf("user ID not found in token claims")
}

// Get2FAVerifiedFromClaims extracts the 2FA verification status from JWT claims
func Get2FAVerifiedFromClaims(claims jwt.Claims) (bool, error) {
	// First try to get from extra_claims
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid claims format")
	}

	// Try to extract from extra_claims
	extraClaimsRaw, ok := mapClaims["extra_claims"]
	if !ok {
		return false, fmt.Errorf("extra_claims not found in token")
	}

	extraClaims, ok := extraClaimsRaw.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("extra_claims has invalid format")
	}

	// Look for 2fa_verified in extra claims
	twofaVerified, ok := extraClaims["2fa_verified"]
	if !ok {
		return false, fmt.Errorf("2fa_verified not found in token claims")
	}

	return twofaVerified.(bool), nil
}
