-- +goose Up
-- +goose StatementBegin
ALTER TABLE login ADD COLUMN password_updated_at TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE login ADD COLUMN password_expires_at TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE login ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE login ADD COLUMN locked_until TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE login ADD COLUMN last_failed_attempt_at TIMESTAMP WITHOUT TIME ZONE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login DROP COLUMN IF EXISTS password_updated_at;
ALTER TABLE login DROP COLUMN IF EXISTS password_expires_at;
ALTER TABLE login DROP COLUMN IF EXISTS failed_login_attempts;
ALTER TABLE login DROP COLUMN IF EXISTS locked_until;
ALTER TABLE login DROP COLUMN IF EXISTS last_failed_attempt_at;
-- +goose StatementEnd
