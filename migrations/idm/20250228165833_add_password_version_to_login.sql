-- +goose Up
-- +goose StatementBegin
ALTER TABLE login ADD COLUMN password_version INTEGER DEFAULT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login DROP COLUMN IF EXISTS password_version;
-- +goose StatementEnd
