-- +goose Up
-- +goose StatementBegin
ALTER TABLE roles RENAME COLUMN role_name TO name;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE roles RENAME COLUMN name TO role_name;
-- +goose StatementEnd
