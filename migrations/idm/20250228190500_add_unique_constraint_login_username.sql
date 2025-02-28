-- +goose Up
-- +goose StatementBegin
-- Add unique constraint to login.username
ALTER TABLE login ADD CONSTRAINT login_username_key UNIQUE (username);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop the unique constraint on login.username
ALTER TABLE login DROP CONSTRAINT IF EXISTS login_username_key;
-- +goose StatementEnd
