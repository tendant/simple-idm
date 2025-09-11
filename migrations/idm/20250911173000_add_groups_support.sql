-- +goose Up
-- +goose StatementBegin
-- Migration: Add Groups Support for OIDC
-- Date: 2025-09-11
-- Description: Add groups and user_groups tables to support OIDC groups claim

-- Create groups table with soft delete support
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    deleted_at TIMESTAMP NULL
);

-- Create user-group associations with soft delete support
CREATE TABLE user_groups (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    deleted_at TIMESTAMP NULL,
    PRIMARY KEY (user_id, group_id)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_groups_name ON groups USING btree (name);
CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups USING btree (user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups USING btree (group_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop indexes
DROP INDEX IF EXISTS idx_user_groups_group_id;
DROP INDEX IF EXISTS idx_user_groups_user_id;
DROP INDEX IF EXISTS idx_groups_name;

-- Drop tables
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS groups;
-- +goose StatementEnd
