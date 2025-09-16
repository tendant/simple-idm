-- Migration to add JWKS support for key rotation
-- +goose Up

-- Create JWKS keys table for storing RSA key pairs
CREATE TABLE IF NOT EXISTS jwks_keys (
    kid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alg VARCHAR(10) NOT NULL DEFAULT 'RS256',
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    active BOOLEAN NOT NULL DEFAULT FALSE
);

-- Create partial unique index to ensure only one active key at a time
CREATE UNIQUE INDEX IF NOT EXISTS idx_jwks_keys_active_unique ON jwks_keys(active) WHERE active = TRUE;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_jwks_keys_created_at ON jwks_keys(created_at);

-- +goose Down

-- Drop indexes first
DROP INDEX IF EXISTS idx_jwks_keys_created_at;
DROP INDEX IF EXISTS idx_jwks_keys_active_unique;

-- Drop the JWKS keys table
DROP TABLE IF EXISTS jwks_keys;
