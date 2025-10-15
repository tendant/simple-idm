-- +goose Up
CREATE TABLE roles (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    role_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT
);


-- +goose Down
DROP TABLE IF EXISTS roles;