-- +goose Up
-- +goose StatementBegin
ALTER TABLE login
    ADD CONSTRAINT login_uuid_unique UNIQUE (uuid);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login
    DROP CONSTRAINT IF EXISTS login_uuid_unique;
-- +goose StatementEnd
