package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

// StringPtr returns a pointer to the string value passed in
func StringPtr(s string) *string {
	return &s
}

func ToNullString(str string) sql.NullString {
	if str == "" {
		return sql.NullString{
			String: str,
			Valid:  false,
		}
	}
	return sql.NullString{
		String: str,
		Valid:  true,
	}
}

func GetValidStrings(nullStrings []sql.NullString) []string {
	var validStrings []string

	for _, ns := range nullStrings {
		if ns.Valid {
			validStrings = append(validStrings, ns.String)
		}
	}

	return validStrings
}

// GenerateRandomString generates a secure random string of the specified length
func GenerateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		// In case of error, fall back to a less secure but functional method
		for i := range b {
			b[i] = byte(RandomInt(256))
		}
	}

	return base64.URLEncoding.EncodeToString(b)[:length]
}

// RandomInt returns a random integer between 0 and max-1
func RandomInt(max int) int {
	if max <= 0 {
		return 0
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Fallback in case of error
		return 0
	}

	return int(nBig.Int64())
}

// ParseUUID converts a string to a UUID
func ParseUUID(id string) uuid.UUID {
	parsed, err := uuid.Parse(id)
	if err != nil {
		// Return a nil UUID in case of error
		return uuid.Nil
	}
	return parsed
}

// ShuffleRunes randomly shuffles the order of runes in a slice
func ShuffleRunes(runes []rune) {
	n := len(runes)
	for i := n - 1; i > 0; i-- {
		j := RandomInt(i + 1)
		runes[i], runes[j] = runes[j], runes[i]
	}
}

// hashEmail generates a SHA-256 hash of the email.
func HashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// GetShortHashEmail generates a shorter username from the email hash
// by taking the first 8 characters of the hash
func GetShortHashEmail(email string) string {
	fullHash := HashEmail(email)
	if len(fullHash) <= 8 {
		return fullHash
	}
	return fullHash[:8]
}

// hashPhone generates a SHA-256 hash of the phone number.
func HashPhone(phone string) string {
	hash := sha256.Sum256([]byte(phone))
	return hex.EncodeToString(hash[:])
}

// maskEmail masks part of the email for display.
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email // Return as is if it's not a valid email
	}
	localPart := parts[0]
	domain := parts[1]

	// Show first and last character, mask the middle
	if len(localPart) > 2 {
		return localPart[:1] + "***" + localPart[len(localPart)-1:] + "@" + domain
	} else if len(localPart) == 2 {
		return localPart[:1] + "*" + localPart[1:] + "@" + domain
	}
	return localPart + "@" + domain // For single character local parts, don't mask
}

// MaskPhone masks a phone number, showing only the last 4 digits
func MaskPhone(phone string) string {
	if len(phone) <= 4 {
		return phone
	}
	return strings.Repeat("*", len(phone)-4) + phone[len(phone)-4:]
}

// NullStringToNullUUID converts a sql.NullString to uuid.NullUUID
func NullStringToNullUUID(nullStr sql.NullString) uuid.NullUUID {
	if !nullStr.Valid {
		return uuid.NullUUID{
			UUID:  uuid.UUID{},
			Valid: false,
		}
	}

	id, err := uuid.Parse(nullStr.String)
	if err != nil {
		return uuid.NullUUID{
			UUID:  uuid.UUID{},
			Valid: false,
		}
	}

	return uuid.NullUUID{
		UUID:  id,
		Valid: true,
	}
}

func ToNullUUID(id uuid.UUID) uuid.NullUUID {
	if id == uuid.Nil {
		return uuid.NullUUID{
			Valid: false,
		}
	}
	return uuid.NullUUID{
		UUID:  id,
		Valid: true,
	}
}
