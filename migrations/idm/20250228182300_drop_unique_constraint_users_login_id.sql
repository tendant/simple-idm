-- +goose Up
-- +goose StatementBegin
-- Drop the unique constraint on users.login_id
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_login_uuid_key;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Re-add the unique constraint on users.login_id
ALTER TABLE users ADD CONSTRAINT users_login_uuid_key UNIQUE (login_id);
-- +goose StatementEnd
