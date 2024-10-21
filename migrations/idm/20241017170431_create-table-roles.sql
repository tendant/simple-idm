-- +goose Up
CREATE TABLE roles (
    uuid uuid PRIMARY KEY DEFAULT uuid_generate_v4() NOT NULL,
    role_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT
);


-- +goose Down
DROP TABLE IF EXISTS roles;