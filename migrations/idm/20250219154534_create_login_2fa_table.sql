-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS login_2fa (
    uuid UUID DEFAULT uuid_generate_v4() NOT NULL PRIMARY KEY,
    login_uuid UUID NOT NULL REFERENCES login(uuid),
    two_factor_secret TEXT,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_type VARCHAR(48),
    two_factor_backup_codes TEXT[],
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    deleted_at TIMESTAMP WITHOUT TIME ZONE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS login_2fa;
-- +goose StatementEnd
