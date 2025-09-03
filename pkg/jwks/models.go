package jwks

import (
	"crypto/rsa"
	"encoding/json"
)

// JWKS represents a JSON Web Key Set as defined in RFC 7517
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key as defined in RFC 7517
type JWK struct {
	// Key Type - "RSA" for RSA keys
	Kty string `json:"kty"`

	// Public Key Use - "sig" for signature
	Use string `json:"use"`

	// Key ID - unique identifier for this key
	Kid string `json:"kid"`

	// Algorithm - "RS256" for RSA with SHA-256
	Alg string `json:"alg,omitempty"`

	// RSA public key modulus (base64url encoded)
	N string `json:"n"`

	// RSA public key exponent (base64url encoded)
	E string `json:"e"`
}

// KeyPair represents an RSA key pair with metadata
type KeyPair struct {
	// Key ID - unique identifier
	Kid string `json:"kid"`

	// Algorithm used with this key
	Alg string `json:"alg"`

	// RSA private key
	PrivateKey *rsa.PrivateKey `json:"-"`

	// RSA public key (derived from private key)
	PublicKey *rsa.PublicKey `json:"-"`

	// Creation timestamp
	CreatedAt int64 `json:"created_at"`

	// Whether this is the active signing key
	Active bool `json:"active"`
}

// ToJWK converts a KeyPair to a JWK (public key only)
func (kp *KeyPair) ToJWK() *JWK {
	return &JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kp.Kid,
		Alg: kp.Alg,
		N:   encodeRSAPublicKeyModulus(kp.PublicKey),
		E:   encodeRSAPublicKeyExponent(kp.PublicKey),
	}
}

// KeyStore represents the stored key data
type KeyStore struct {
	Keys []KeyPair `json:"keys"`
}

// MarshalJSON implements custom JSON marshaling for KeyPair
func (kp *KeyPair) MarshalJSON() ([]byte, error) {
	type Alias KeyPair
	return json.Marshal(&struct {
		*Alias
		PrivateKeyPEM string `json:"private_key_pem"`
		PublicKeyPEM  string `json:"public_key_pem"`
	}{
		Alias:         (*Alias)(kp),
		PrivateKeyPEM: encodePrivateKeyToPEM(kp.PrivateKey),
		PublicKeyPEM:  encodePublicKeyToPEM(kp.PublicKey),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for KeyPair
func (kp *KeyPair) UnmarshalJSON(data []byte) error {
	type Alias KeyPair
	aux := &struct {
		*Alias
		PrivateKeyPEM string `json:"private_key_pem"`
		PublicKeyPEM  string `json:"public_key_pem"`
	}{
		Alias: (*Alias)(kp),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Decode PEM keys
	privateKey, err := decodePrivateKeyFromPEM(aux.PrivateKeyPEM)
	if err != nil {
		return err
	}
	kp.PrivateKey = privateKey

	publicKey, err := decodePublicKeyFromPEM(aux.PublicKeyPEM)
	if err != nil {
		return err
	}
	kp.PublicKey = publicKey

	return nil
}
