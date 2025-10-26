package bootstrap

import (
	"fmt"
	"log/slog"
	"strings"
)

// PrintRSAKeyResult displays the RSA key bootstrap results in a clean, formatted way
func PrintRSAKeyResult(result *RSAKeyResult) {
	if result == nil {
		return
	}

	// Print section header
	printRSAHeader(result.Generated)

	// Print key information
	printRSAKeyInfo(result)

	// Print security reminders
	printRSASecurityWarnings(result.Generated)

	// Print section footer
	printSectionFooter()
}

// printRSAHeader prints a formatted section header
func printRSAHeader(generated bool) {
	border := strings.Repeat("=", 80)
	fmt.Printf("\n%s\n", border)
	if generated {
		fmt.Printf("🔐 RSA KEY PAIR GENERATED\n")
	} else {
		fmt.Printf("🔐 RSA KEY PAIR LOADED\n")
	}
	fmt.Printf("%s\n", border)
}

// printRSAKeyInfo prints information about the RSA key
func printRSAKeyInfo(result *RSAKeyResult) {
	fmt.Println("\n📋 Key Information:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("  Status:      %s\n", getStatusText(result.Generated))
	fmt.Printf("  Key File:    %s\n", result.KeyPath)
	fmt.Printf("  Key ID:      %s\n", result.KeyID)
	fmt.Printf("  Key Size:    %d bits\n", result.KeySize)
	fmt.Printf("  Fingerprint: %s\n", formatFingerprint(result.Fingerprint))
}

// getStatusText returns a human-readable status text
func getStatusText(generated bool) string {
	if generated {
		return "✨ Newly generated"
	}
	return "✓ Loaded from file"
}

// formatFingerprint formats the fingerprint for display (with colons every 2 chars)
func formatFingerprint(fingerprint string) string {
	if len(fingerprint) < 16 {
		return fingerprint
	}

	// Show first 32 chars (16 bytes) with colons
	shortened := fingerprint[:32]
	var formatted strings.Builder

	for i := 0; i < len(shortened); i += 2 {
		if i > 0 {
			formatted.WriteString(":")
		}
		formatted.WriteString(shortened[i : i+2])
	}

	if len(fingerprint) > 32 {
		formatted.WriteString("...")
	}

	return formatted.String()
}

// printRSASecurityWarnings prints important security warnings
func printRSASecurityWarnings(generated bool) {
	fmt.Println("\n⚠️  SECURITY REMINDERS:")
	fmt.Println(strings.Repeat("-", 80))

	if generated {
		fmt.Println("  • NEW RSA KEY PAIR GENERATED - Back it up securely!")
		fmt.Println("  • Private key stored with permissions 0600 (owner read/write only)")
		fmt.Println("  • Keep the private key file secure and never share it")
		fmt.Println("  • Consider backing up the key to a secure location")
		fmt.Println("  • All JWT tokens will be signed with this key")
		fmt.Println("  • If this key is lost, all existing tokens will be invalidated")
	} else {
		fmt.Println("  • Using existing RSA key pair")
		fmt.Println("  • Ensure the private key file remains secure (permissions 0600)")
		fmt.Println("  • All JWT tokens are signed with this key")
		fmt.Println("  • Backup this key to prevent token invalidation")
	}
}

// LogRSAKeySummary logs a concise summary using slog (for structured logging)
func LogRSAKeySummary(result *RSAKeyResult) {
	if result == nil {
		return
	}

	slog.Info("RSA key bootstrap summary",
		"generated", result.Generated,
		"key_path", result.KeyPath,
		"key_id", result.KeyID,
		"key_size", result.KeySize,
		"fingerprint", result.Fingerprint[:16]+"...", // Log shortened fingerprint
	)
}

// PrintRSAKeyQuietInfo prints minimal info (for non-first-run scenarios)
func PrintRSAKeyQuietInfo(result *RSAKeyResult) {
	if result == nil {
		return
	}

	if result.Generated {
		fmt.Printf("✨ Generated new RSA key: %s (Key ID: %s, %d bits)\n",
			result.KeyPath, result.KeyID, result.KeySize)
	} else {
		fmt.Printf("✓ Loaded RSA key: %s (Key ID: %s, %d bits)\n",
			result.KeyPath, result.KeyID, result.KeySize)
	}
}
