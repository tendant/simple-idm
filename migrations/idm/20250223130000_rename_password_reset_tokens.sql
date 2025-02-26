-- +goose Up
-- +goose StatementBegin
-- Drop existing indexes
DROP INDEX IF EXISTS idx_password_reset_tokens_token;
DROP INDEX IF EXISTS idx_password_reset_tokens_user_uuid;

-- Drop foreign key constraint
ALTER TABLE password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_login_id_fkey;

-- Rename the table
ALTER TABLE password_reset_tokens RENAME TO login_password_reset_tokens;

-- Add foreign key constraint back with new name
ALTER TABLE login_password_reset_tokens ADD CONSTRAINT login_password_reset_tokens_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES login(id);

-- Recreate indexes with new names
CREATE INDEX IF NOT EXISTS idx_login_password_reset_tokens_token 
    ON login_password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_login_password_reset_tokens_login_id 
    ON login_password_reset_tokens(login_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop indexes
DROP INDEX IF EXISTS idx_login_password_reset_tokens_token;
DROP INDEX IF EXISTS idx_login_password_reset_tokens_login_id;

-- Drop foreign key constraint
ALTER TABLE login_password_reset_tokens DROP CONSTRAINT IF EXISTS login_password_reset_tokens_login_id_fkey;

-- Rename the table back
ALTER TABLE login_password_reset_tokens RENAME TO password_reset_tokens;

-- Add foreign key constraint back with old name
ALTER TABLE password_reset_tokens ADD CONSTRAINT password_reset_tokens_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES login(id);

-- Recreate indexes with old names
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token 
    ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_uuid 
    ON password_reset_tokens(login_id);
-- +goose StatementEnd
