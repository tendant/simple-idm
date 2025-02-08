-- +goose Up
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS two_factor_secret TEXT,
    ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS two_factor_backup_codes TEXT[];

-- +goose Down
ALTER TABLE users 
    DROP COLUMN IF EXISTS two_factor_secret,
    DROP COLUMN IF EXISTS two_factor_enabled,
    DROP COLUMN IF EXISTS two_factor_backup_codes;
