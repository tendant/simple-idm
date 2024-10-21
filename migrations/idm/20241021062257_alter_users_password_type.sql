-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
  ALTER COLUMN password TYPE VARCHAR(255);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users
  ALTER COLUMN password TYPE bytea USING decode(password, 'escape');;
-- +goose StatementEnd
