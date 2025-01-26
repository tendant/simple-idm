-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_uuid UUID NOT NULL REFERENCES users(uuid),
    token VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expire_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_user FOREIGN KEY (user_uuid) REFERENCES users(uuid)
);

-- Add index for token lookup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);

-- Add index for user lookup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_uuid ON password_reset_tokens(user_uuid);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_password_reset_tokens_user_uuid;
DROP INDEX IF EXISTS idx_password_reset_tokens_token;
DROP TABLE IF EXISTS password_reset_tokens;
-- +goose StatementEnd
