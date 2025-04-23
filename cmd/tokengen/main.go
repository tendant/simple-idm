package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tendant/simple-idm/pkg/tokengenerator"
)

func main() {
	// Parse command line flags
	secret := flag.String("secret", "your-secret-key", "Secret key for signing the token")
	issuer := flag.String("issuer", "simple-idm", "Issuer of the token")
	audience := flag.String("audience", "public", "Audience of the token")
	subject := flag.String("subject", "test-subject", "Subject of the token (usually user ID)")
	expiry := flag.Duration("expiry", 30*time.Minute, "Token expiry duration (e.g., 30m, 1h, 24h)")
	extraClaimsJSON := flag.String("claims", "{}", "Extra claims in JSON format")
	outputFormat := flag.String("format", "compact", "Output format: compact, full, or debug")
	flag.Parse()

	// Create the token generator
	tokenGen := tokengenerator.NewJwtTokenGenerator(*secret, *issuer, *audience)

	// Parse extra claims
	var extraClaims map[string]interface{}
	if err := json.Unmarshal([]byte(*extraClaimsJSON), &extraClaims); err != nil {
		slog.Error("Failed to parse extra claims JSON", "err", err)
		fmt.Fprintf(os.Stderr, "Error: Failed to parse extra claims JSON: %v\n", err)
		os.Exit(1)
	}

	// Generate the token
	tokenStr, expiryTime, err := tokenGen.GenerateToken(*subject, *expiry, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate token", "err", err)
		fmt.Fprintf(os.Stderr, "Error: Failed to generate token: %v\n", err)
		os.Exit(1)
	}

	// Output the token based on format
	switch *outputFormat {
	case "compact":
		fmt.Println(tokenStr)
	case "full":
		fmt.Printf("Token: %s\nExpires: %s\n", tokenStr, expiryTime.Format(time.RFC3339))
	case "debug":
		// Parse the token to display its contents
		token, err := tokenGen.ParseToken(tokenStr)
		if err != nil {
			slog.Error("Failed to parse generated token", "err", err)
			fmt.Fprintf(os.Stderr, "Error: Failed to parse generated token: %v\n", err)
			os.Exit(1)
		}

		// Get claims as map for easier display
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			slog.Error("Failed to get claims from token")
			fmt.Fprintf(os.Stderr, "Error: Failed to get claims from token\n")
			os.Exit(1)
		}

		// Format the output
		fmt.Printf("=== Token Information ===\n")
		fmt.Printf("Token: %s\n\n", tokenStr)
		fmt.Printf("=== Token Header ===\n")
		headerJSON, _ := json.MarshalIndent(token.Header, "", "  ")
		fmt.Printf("%s\n\n", headerJSON)
		fmt.Printf("=== Token Claims ===\n")
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Printf("%s\n\n", claimsJSON)
		fmt.Printf("Expires: %s\n", expiryTime.Format(time.RFC3339))
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown output format: %s\n", *outputFormat)
		os.Exit(1)
	}
}
