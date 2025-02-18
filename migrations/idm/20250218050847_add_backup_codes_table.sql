-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS backup_codes (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_uuid UUID NOT NULL REFERENCES users(uuid),
    code TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_uuid, code)
);

CREATE INDEX IF NOT EXISTS idx_backup_codes_user_uuid ON backup_codes(user_uuid);
CREATE INDEX IF NOT EXISTS idx_backup_codes_code ON backup_codes(code);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backup_codes;
-- +goose StatementEnd
