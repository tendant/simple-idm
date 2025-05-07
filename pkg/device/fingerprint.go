package device

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// FingerprintData contains the components used to generate a device fingerprint
type FingerprintData struct {
	UserAgent        string
	AcceptHeaders    string
	Timezone         string
	ScreenResolution string
	DeviceID         string // For mobile devices
	IsMobile         bool   // Flag to indicate if this is a mobile device
}

// GenerateFingerprint creates a unique fingerprint for a device based on the provided data
// The fingerprint is a SHA-256 hash of the combined data
// For web: hash of User-Agent, Accept-Headers, Screen Resolution, and Timezone
// For mobile: hash of Device ID only
func GenerateFingerprint(data FingerprintData) string {
	var combined string

	if data.IsMobile && data.DeviceID != "" {
		// For mobile devices, use only the device ID
		combined = data.DeviceID
	} else {
		// For web browsers, use the standard combination
		combined = fmt.Sprintf("%s|%s|%s|%s",
			data.UserAgent,
			data.AcceptHeaders,
			data.Timezone,
			data.ScreenResolution,
		)
	}

	// Create a SHA-256 hash of the combined data
	hash := sha256.Sum256([]byte(combined))

	// Convert the hash to a hex string
	return hex.EncodeToString(hash[:])
}

// ExtractFingerprintDataFromRequest extracts fingerprint data from an HTTP request
func ExtractFingerprintDataFromRequest(r *http.Request) FingerprintData {
	// Check if the request is from a mobile device by looking for the Device-ID header
	deviceID := r.Header.Get("X-Device-ID")
	isMobile := deviceID != ""

	// Get the Accept headers
	acceptHeaders := r.Header.Get("Accept") + "|" +
		r.Header.Get("Accept-Language") + "|" +
		r.Header.Get("Accept-Encoding")

	// If no explicit device ID is provided, check if the User-Agent indicates a mobile device
	if !isMobile && isMobileUserAgent(r.UserAgent()) {
		slog.Error("Mobile device detected but no device ID provided")
		isMobile = true
	}

	return FingerprintData{
		UserAgent:        r.UserAgent(),
		AcceptHeaders:    acceptHeaders,
		Timezone:         r.Header.Get("Timezone"),
		ScreenResolution: r.Header.Get("Screen-Resolution"),
		DeviceID:         deviceID,
		IsMobile:         isMobile,
	}
}

// GetRequestFingerprint is a convenience function that extracts data from a request
// and generates a fingerprint in one step
func GetRequestFingerprint(r *http.Request) string {
	data := ExtractFingerprintDataFromRequest(r)
	return GenerateFingerprint(data)
}

// isMobileUserAgent checks if the user agent string indicates a mobile device
func isMobileUserAgent(userAgent string) bool {
	userAgentLower := strings.ToLower(userAgent)
	mobileKeywords := []string{
		"android", "iphone", "ipad", "ipod", "windows phone", "blackberry",
		"mobile", "tablet", "opera mini", "opera mobi", "safari/", "samsung",
		"nokia", "symbian", "webos", "palm", "midp", "j2me", "wap", "mobile safari",
	}

	for _, keyword := range mobileKeywords {
		if strings.Contains(userAgentLower, keyword) {
			return true
		}
	}

	return false
}
