package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
)

type Handle struct {
	// Global Fosite OAuth2 Provider
	OAuth2Provider fosite.OAuth2Provider

	// RSA Private Key for signing ID tokens
	PrivateKey *rsa.PrivateKey
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile("private.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func NewHandle() *Handle {
	// Generate RSA Key for signing ID Tokens
	privateKey, err := loadPrivateKey()
	if err != nil {
		slog.Error("Could not load RSA Private Key:", "err", err)
	}

	// In-memory OAuth2 storage (Replace with a database in production)
	store := storage.NewExampleStore()

	// Fosite Config
	config := &fosite.Config{
		AccessTokenLifespan: time.Hour,
		GlobalSecret:        []byte("some-secret"),
	}

	// Define Fosite configuration with OIDC support
	oauth2Provider := compose.ComposeAllEnabled(
		config,
		store,
		privateKey,
	)
	return &Handle{
		OAuth2Provider: oauth2Provider,
		PrivateKey:     privateKey,
	}
}
