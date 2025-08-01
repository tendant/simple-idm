-- +goose Up
-- +goose StatementBegin
-- Add login_magic_link_tokens table
CREATE TABLE IF NOT EXISTS login_magic_link_tokens (
    id uuid DEFAULT uuid_generate_v4() NOT NULL PRIMARY KEY,
    login_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone,
    CONSTRAINT login_magic_link_tokens_login_id_fkey FOREIGN KEY (login_id) REFERENCES login(id)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_login_magic_link_tokens_token ON login_magic_link_tokens USING btree (token);
CREATE INDEX IF NOT EXISTS idx_login_magic_link_tokens_login_id ON login_magic_link_tokens USING btree (login_id);

-- Add is_passwordless column to login table
ALTER TABLE login ADD COLUMN IF NOT EXISTS is_passwordless boolean DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop indexes
DROP INDEX IF EXISTS idx_login_magic_link_tokens_token;
DROP INDEX IF EXISTS idx_login_magic_link_tokens_login_id;

-- Drop table
DROP TABLE IF EXISTS login_magic_link_tokens;

-- Remove column
ALTER TABLE login DROP COLUMN IF EXISTS is_passwordless;
-- +goose StatementEnd
