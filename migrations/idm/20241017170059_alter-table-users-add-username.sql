-- +goose Up
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255);


-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS username;