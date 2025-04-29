package device

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
)

// FingerprintData contains the components used to generate a device fingerprint
type FingerprintData struct {
	UserAgent        string
	AcceptHeaders    string
	Timezone         string
	ScreenResolution string
	// Additional fields that could be used:
	// - Browser plugins
	// - Canvas fingerprint
	// - WebGL fingerprint
}

// GenerateFingerprint creates a unique fingerprint for a device based on the provided data
// The fingerprint is a SHA-256 hash of the combined data
func GenerateFingerprint(data FingerprintData) string {
	// Combine the data into a single string
	combined := fmt.Sprintf("%s|%s|%s|%s",
		data.UserAgent,
		data.AcceptHeaders,
		data.Timezone,
		data.ScreenResolution,
	)

	// Create a SHA-256 hash of the combined data
	hash := sha256.Sum256([]byte(combined))

	// Convert the hash to a hex string
	return hex.EncodeToString(hash[:])
}

// ExtractFingerprintDataFromRequest extracts fingerprint data from an HTTP request
func ExtractFingerprintDataFromRequest(r *http.Request) FingerprintData {
	// Get the Accept headers
	acceptHeaders := r.Header.Get("Accept") + "|" +
		r.Header.Get("Accept-Language") + "|" +
		r.Header.Get("Accept-Encoding")

	return FingerprintData{
		UserAgent:        r.UserAgent(),
		AcceptHeaders:    acceptHeaders,
		Timezone:         "", // TODO: implement timezone extraction
		ScreenResolution: "", // TODO: implement screen resolution extraction
	}
}

// GetRequestFingerprint is a convenience function that extracts data from a request
// and generates a fingerprint in one step
func GetRequestFingerprint(r *http.Request) string {
	data := ExtractFingerprintDataFromRequest(r)
	return GenerateFingerprint(data)
}
