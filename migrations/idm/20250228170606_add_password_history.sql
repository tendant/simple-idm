-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS login_password_history (
    id UUID DEFAULT gen_random_uuid() NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    deleted_at TIMESTAMP WITHOUT TIME ZONE,
    login_id UUID NOT NULL,
    password_hash BYTEA NOT NULL,
    password_version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT login_password_history_pkey PRIMARY KEY (id),
    CONSTRAINT login_password_history_login_id_fkey FOREIGN KEY (login_id) REFERENCES login(id)
);

-- Create index for faster password history lookups
CREATE INDEX login_password_history_login_id_idx ON login_password_history(login_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS login_password_history;
-- +goose StatementEnd
