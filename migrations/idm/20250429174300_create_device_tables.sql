-- +goose Up
-- +goose StatementBegin
-- Device table for storing device fingerprinting information
CREATE TABLE device (
    fingerprint VARCHAR(255) NOT NULL,
    user_agent TEXT NOT NULL,
    accept_headers TEXT,
    timezone VARCHAR(100),
    screen_resolution VARCHAR(50),
    last_login TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    PRIMARY KEY (fingerprint)
);

-- LoginDevice table for linking devices to logins with 90-day expiration
CREATE TABLE login_device (
    id UUID DEFAULT uuid_generate_v4() NOT NULL,
    login_id UUID NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,
    linked_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITHOUT TIME ZONE,
    PRIMARY KEY (id),
    FOREIGN KEY (fingerprint) REFERENCES device(fingerprint),
    FOREIGN KEY (login_id) REFERENCES login(id)
);

-- Add indexes for better query performance
CREATE INDEX idx_login_device_login_id ON login_device(login_id);
CREATE INDEX idx_login_device_fingerprint ON login_device(fingerprint);
CREATE INDEX idx_login_device_expires_at ON login_device(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop indexes first
DROP INDEX IF EXISTS idx_login_device_expires_at;
DROP INDEX IF EXISTS idx_login_device_fingerprint;
DROP INDEX IF EXISTS idx_login_device_login_id;

-- Drop tables in reverse order to avoid foreign key constraint issues
DROP TABLE IF EXISTS login_device;
DROP TABLE IF EXISTS device;
-- +goose StatementEnd
