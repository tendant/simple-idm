-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
ADD COLUMN IF NOT EXISTS login_uuid uuid UNIQUE REFERENCES login(uuid);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users 
    DROP COLUMN IF EXISTS login_uuid;
-- +goose StatementEnd
