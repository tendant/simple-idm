-- +goose Up
-- +goose StatementBegin
CREATE TABLE login_attempt (
    id UUID DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    login_id UUID NOT NULL REFERENCES login(id),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    device_fingerprint VARCHAR(255)
);

CREATE INDEX login_attempt_login_id_idx ON login_attempt(login_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS login_attempt_login_id_idx;
DROP TABLE IF EXISTS login_attempt;
-- +goose StatementEnd
