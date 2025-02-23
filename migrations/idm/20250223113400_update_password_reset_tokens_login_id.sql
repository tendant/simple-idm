-- +goose Up
-- +goose StatementBegin
-- Drop existing foreign key constraint
ALTER TABLE public.password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_user_id_fkey CASCADE;

-- Add login_id column
ALTER TABLE public.password_reset_tokens ADD COLUMN login_id UUID;

-- Update login_id values from users table
UPDATE public.password_reset_tokens prt
SET login_id = u.login_id
FROM public.users u
WHERE prt.user_id = u.id
AND u.login_id IS NOT NULL;

-- Delete any password reset tokens that don't have a valid login_id
DELETE FROM public.password_reset_tokens
WHERE login_id IS NULL
OR expire_at < NOW()
OR used_at IS NOT NULL;

-- Make login_id not null
ALTER TABLE public.password_reset_tokens ALTER COLUMN login_id SET NOT NULL;

-- Drop user_id column
ALTER TABLE public.password_reset_tokens DROP COLUMN user_id;

-- Add foreign key constraint to login table
ALTER TABLE public.password_reset_tokens ADD CONSTRAINT password_reset_tokens_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES public.login(id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Add user_id column
ALTER TABLE public.password_reset_tokens ADD COLUMN user_id UUID;

-- Update user_id values from users table
UPDATE public.password_reset_tokens prt
SET user_id = u.id
FROM public.users u
WHERE prt.login_id = u.login_id;

-- Drop foreign key constraint
ALTER TABLE public.password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_login_id_fkey CASCADE;

-- Drop login_id column
ALTER TABLE public.password_reset_tokens DROP COLUMN login_id;

-- Add foreign key constraint back to users table
ALTER TABLE public.password_reset_tokens ADD CONSTRAINT password_reset_tokens_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES public.users(id);

-- Make user_id not null
ALTER TABLE public.password_reset_tokens ALTER COLUMN user_id SET NOT NULL;
-- +goose StatementEnd
