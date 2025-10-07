-- +goose Up
-- Add email verification columns to users table
ALTER TABLE users
    ADD COLUMN email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    ADD COLUMN email_verified_at TIMESTAMP WITHOUT TIME ZONE;

-- Create email verification tokens table
CREATE TABLE email_verification_tokens (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    token VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'UTC') NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITHOUT TIME ZONE,
    deleted_at TIMESTAMP WITHOUT TIME ZONE
);

-- Create indexes for email verification tokens
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_token ON email_verification_tokens(token)
    WHERE deleted_at IS NULL AND verified_at IS NULL;
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at)
    WHERE deleted_at IS NULL;

-- Add partial unique index on email (enforces uniqueness only for active users)
-- This allows email reuse after account deletion (soft delete)
CREATE UNIQUE INDEX idx_users_email_active ON users(email)
    WHERE deleted_at IS NULL;

-- Add index on email_verified for queries
CREATE INDEX idx_users_email_verified ON users(email_verified)
    WHERE deleted_at IS NULL;

-- +goose Down
-- Remove indexes
DROP INDEX IF EXISTS idx_users_email_verified;
DROP INDEX IF EXISTS idx_users_email_active;
DROP INDEX IF EXISTS idx_email_verification_tokens_expires_at;
DROP INDEX IF EXISTS idx_email_verification_tokens_token;
DROP INDEX IF EXISTS idx_email_verification_tokens_user_id;

-- Drop email verification tokens table
DROP TABLE IF EXISTS email_verification_tokens;

-- Remove email verification columns from users table
ALTER TABLE users
    DROP COLUMN IF EXISTS email_verified_at,
    DROP COLUMN IF EXISTS email_verified;
