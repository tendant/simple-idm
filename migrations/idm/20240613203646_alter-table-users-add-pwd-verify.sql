-- +goose Up
ALTER TABLE users ADD COLUMN IF NOT EXISTS password BYTEA, ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP;


-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS password, verified_at;