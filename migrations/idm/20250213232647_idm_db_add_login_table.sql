-- +goose Up
-- +goose StatementBegin
CREATE TABLE login (
    uuid UUID DEFAULT gen_random_uuid() NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    deleted_at TIMESTAMP WITHOUT TIME ZONE,
    created_by VARCHAR(255),
    password BYTEA,
    username VARCHAR(255),
    two_factor_secret TEXT,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_backup_codes TEXT[],
    CONSTRAINT login_uuid_pk PRIMARY KEY (uuid)  -- Explicit primary key constraint
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS login;
-- +goose StatementEnd
