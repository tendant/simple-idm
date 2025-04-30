-- +goose Up
-- +goose StatementBegin
ALTER TABLE login ADD COLUMN password_updated_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE login ADD COLUMN password_expire_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE login ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE login ADD COLUMN locked_until TIMESTAMP WITH TIME ZONE;
ALTER TABLE login ADD COLUMN last_failed_attempt_at TIMESTAMP WITH TIME ZONE;

-- Set default values for existing records
UPDATE login 
SET password_updated_at = updated_at,
    password_expire_at = updated_at + INTERVAL '90 days',
    failed_login_attempts = 0
WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login DROP COLUMN IF EXISTS password_updated_at;
ALTER TABLE login DROP COLUMN IF EXISTS password_expire_at;
ALTER TABLE login DROP COLUMN IF EXISTS failed_login_attempts;
ALTER TABLE login DROP COLUMN IF EXISTS locked_until;
ALTER TABLE login DROP COLUMN IF EXISTS last_failed_attempt_at;
-- +goose StatementEnd
