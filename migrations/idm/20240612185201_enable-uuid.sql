-- +goose Up
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


-- +goose Down
DROP EXTENSION IF EXISTS "uuid-ossp";
