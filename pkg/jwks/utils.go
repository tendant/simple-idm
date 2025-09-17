package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// EncodeRSAPublicKeyModulus encodes the RSA public key modulus as base64url
func EncodeRSAPublicKeyModulus(publicKey *rsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
}

// EncodeRSAPublicKeyExponent encodes the RSA public key exponent as base64url
func EncodeRSAPublicKeyExponent(publicKey *rsa.PublicKey) string {
	exponentBytes := big.NewInt(int64(publicKey.E)).Bytes()
	return base64.RawURLEncoding.EncodeToString(exponentBytes)
}

// EncodePrivateKeyToPEM encodes an RSA private key to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

// EncodePublicKeyToPEM encodes an RSA public key to PEM format
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM)
}

// DecodePrivateKeyFromPEM decodes an RSA private key from PEM format
// Supports both PKCS#1 (RSA PRIVATE KEY) and PKCS#8 (PRIVATE KEY) formats
func DecodePrivateKeyFromPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var privateKey *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
	case "PRIVATE KEY":
		// PKCS#8 format
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}

		var ok bool
		privateKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parsed key is not an RSA private key")
		}
	default:
		return nil, fmt.Errorf("invalid PEM block type: %s (expected RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}

	return privateKey, nil
}

// DecodePublicKeyFromPEM decodes an RSA public key from PEM format
func DecodePublicKeyFromPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return publicKey, nil
}
