package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/tendant/simple-idm/pkg/jwks"
)

// RSAKeyConfig contains configuration for RSA key bootstrap
type RSAKeyConfig struct {
	// Path to the private key file (e.g., "jwt-private.pem")
	KeyFile string

	// Key size in bits (2048, 3072, or 4096)
	// Default: 2048
	KeySize int

	// Key ID prefix (e.g., "quick-idm", "loginv2")
	// Default: "idm"
	KeyIDPrefix string
}

// RSAKeyResult contains the result of RSA key bootstrap
type RSAKeyResult struct {
	// The private key
	PrivateKey *rsa.PrivateKey

	// Key ID (derived from fingerprint)
	KeyID string

	// Absolute path to key file
	KeyPath string

	// Whether the key was newly generated (true) or loaded from file (false)
	Generated bool

	// Key size in bits
	KeySize int

	// Fingerprint (SHA-256 hash of public key)
	Fingerprint string
}

// BootstrapRSAKey ensures an RSA private key exists, generating one if needed
// Returns the key, key ID, and information about what was done
func BootstrapRSAKey(cfg RSAKeyConfig) (*RSAKeyResult, error) {
	// Validate and set defaults
	if err := validateRSAConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid RSA key configuration: %w", err)
	}

	// Resolve absolute path
	keyPath, err := resolveKeyPath(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key path: %w", err)
	}

	// Check if key exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return generateNewKey(keyPath, cfg)
	}

	// Load existing key
	return loadExistingKey(keyPath, cfg)
}

// validateRSAConfig validates and sets defaults for RSA configuration
func validateRSAConfig(cfg *RSAKeyConfig) error {
	if cfg.KeyFile == "" {
		return fmt.Errorf("KeyFile is required")
	}

	// Set default key size
	if cfg.KeySize == 0 {
		cfg.KeySize = 2048
	}

	// Validate key size
	if cfg.KeySize != 2048 && cfg.KeySize != 3072 && cfg.KeySize != 4096 {
		return fmt.Errorf("invalid key size %d (must be 2048, 3072, or 4096)", cfg.KeySize)
	}

	// Set default key ID prefix
	if cfg.KeyIDPrefix == "" {
		cfg.KeyIDPrefix = "idm"
	}

	return nil
}

// resolveKeyPath resolves the key file path to an absolute path
func resolveKeyPath(keyFile string) (string, error) {
	if filepath.IsAbs(keyFile) {
		return keyFile, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	return filepath.Join(cwd, keyFile), nil
}

// generateNewKey generates a new RSA private key and saves it to file
func generateNewKey(keyPath string, cfg RSAKeyConfig) (*RSAKeyResult, error) {
	slog.Info("RSA key not found - generating new key pair",
		"path", keyPath,
		"key_size", cfg.KeySize)

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Write to file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	// Set restrictive permissions (owner read/write only)
	if err := os.Chmod(keyPath, 0600); err != nil {
		slog.Warn("Failed to set key file permissions", "error", err, "path", keyPath)
		// Don't fail - just warn
	}

	// Calculate fingerprint and key ID
	fingerprint := calculateFingerprint(&privateKey.PublicKey)
	keyID := fmt.Sprintf("%s-%s", cfg.KeyIDPrefix, fingerprint[:12])

	slog.Info("RSA key generated successfully",
		"path", keyPath,
		"key_id", keyID,
		"key_size", cfg.KeySize,
		"fingerprint", fingerprint)

	return &RSAKeyResult{
		PrivateKey:  privateKey,
		KeyID:       keyID,
		KeyPath:     keyPath,
		Generated:   true,
		KeySize:     cfg.KeySize,
		Fingerprint: fingerprint,
	}, nil
}

// loadExistingKey loads an existing RSA private key from file
func loadExistingKey(keyPath string, cfg RSAKeyConfig) (*RSAKeyResult, error) {
	slog.Info("Loading existing RSA key", "path", keyPath)

	// Read key file
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decode private key
	privateKey, err := jwks.DecodePrivateKeyFromPEM(string(keyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Calculate fingerprint and key ID
	fingerprint := calculateFingerprint(&privateKey.PublicKey)
	keyID := fmt.Sprintf("%s-%s", cfg.KeyIDPrefix, fingerprint[:12])

	// Determine key size
	keySize := privateKey.N.BitLen()

	slog.Info("RSA key loaded successfully",
		"path", keyPath,
		"key_id", keyID,
		"key_size", keySize,
		"fingerprint", fingerprint)

	return &RSAKeyResult{
		PrivateKey:  privateKey,
		KeyID:       keyID,
		KeyPath:     keyPath,
		Generated:   false,
		KeySize:     keySize,
		Fingerprint: fingerprint,
	}, nil
}

// calculateFingerprint calculates a SHA-256 fingerprint of the RSA public key
func calculateFingerprint(publicKey *rsa.PublicKey) string {
	// Marshal public key to DER format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Warn("Failed to marshal public key for fingerprint", "error", err)
		return "unknown"
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(pubKeyBytes)

	// Return hex encoded fingerprint
	return hex.EncodeToString(hash[:])
}

// ExportPublicKey exports the public key in PEM format
func ExportPublicKey(result *RSAKeyResult, outputPath string) error {
	if result == nil || result.PrivateKey == nil {
		return fmt.Errorf("invalid RSA key result")
	}

	// Marshal public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&result.PrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create PEM block
	pubKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Write to file
	pubKeyFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubKeyFile.Close()

	if err := pem.Encode(pubKeyFile, pubKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	slog.Info("Public key exported", "path", outputPath)
	return nil
}
