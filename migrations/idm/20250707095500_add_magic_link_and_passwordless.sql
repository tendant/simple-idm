-- +goose Up
-- +goose StatementBegin
-- Add login_magic_link_tokens table
CREATE TABLE IF NOT EXISTS public.login_magic_link_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    login_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone,
    PRIMARY KEY (id),
    CONSTRAINT login_magic_link_tokens_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_login_magic_link_tokens_token ON public.login_magic_link_tokens USING btree (token);
CREATE INDEX IF NOT EXISTS idx_login_magic_link_tokens_login_id ON public.login_magic_link_tokens USING btree (login_id);

-- Add is_passwordless column to login table
ALTER TABLE public.login ADD COLUMN IF NOT EXISTS is_passwordless boolean DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop indexes
DROP INDEX IF EXISTS idx_login_magic_link_tokens_token;
DROP INDEX IF EXISTS idx_login_magic_link_tokens_login_id;

-- Drop table
DROP TABLE IF EXISTS public.login_magic_link_tokens;

-- Remove column
ALTER TABLE public.login DROP COLUMN IF EXISTS is_passwordless;
-- +goose StatementEnd
