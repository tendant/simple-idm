-- +goose Up
-- +goose StatementBegin
-- Drop the unique constraint on username in login table
ALTER TABLE login DROP CONSTRAINT IF EXISTS login_username_key;

-- Modify login_password_reset_tokens table to use UTC time for created_at
ALTER TABLE login_password_reset_tokens 
ALTER COLUMN created_at SET DEFAULT (NOW() at time zone 'UTC');

-- Update existing records to use UTC time
UPDATE login_password_reset_tokens
SET created_at = created_at AT TIME ZONE 'UTC'
WHERE created_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Re-add the unique constraint on username in login table
ALTER TABLE login ADD CONSTRAINT login_username_key UNIQUE (username);

-- Revert login_password_reset_tokens table to use local time for created_at
ALTER TABLE login_password_reset_tokens 
ALTER COLUMN created_at SET DEFAULT (NOW());

-- No need to revert the existing records as this would be complex and potentially lossy
-- +goose StatementEnd
