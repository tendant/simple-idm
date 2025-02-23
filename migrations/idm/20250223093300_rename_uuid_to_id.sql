-- +goose Up
-- +goose StatementBegin
-- Drop foreign key constraints first
ALTER TABLE public.backup_codes DROP CONSTRAINT IF EXISTS backup_codes_user_uuid_fkey CASCADE;
ALTER TABLE public.login_2fa DROP CONSTRAINT IF EXISTS login_2fa_login_uuid_fkey CASCADE;
ALTER TABLE public.password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_user_uuid_fkey CASCADE;
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_role_uuid_fkey CASCADE;
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_user_uuid_fkey CASCADE;
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_login_uuid_fkey CASCADE;

-- Drop primary key and unique constraints
ALTER TABLE public.backup_codes DROP CONSTRAINT IF EXISTS backup_codes_pkey CASCADE;
ALTER TABLE public.login DROP CONSTRAINT IF EXISTS login_uuid_unique CASCADE;
ALTER TABLE public.login_2fa DROP CONSTRAINT IF EXISTS login_2fa_pkey CASCADE;
ALTER TABLE public.password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_pkey CASCADE;
ALTER TABLE public.roles DROP CONSTRAINT IF EXISTS roles_pkey CASCADE;
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_pkey CASCADE;
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey CASCADE;

-- Rename primary key columns
ALTER TABLE public.backup_codes RENAME COLUMN uuid TO id;
ALTER TABLE public.login RENAME COLUMN uuid TO id;
ALTER TABLE public.login_2fa RENAME COLUMN uuid TO id;
ALTER TABLE public.password_reset_tokens RENAME COLUMN uuid TO id;
ALTER TABLE public.roles RENAME COLUMN uuid TO id;
ALTER TABLE public.users RENAME COLUMN uuid TO id;

-- Rename foreign key columns
ALTER TABLE public.backup_codes RENAME COLUMN user_uuid TO user_id;
ALTER TABLE public.login_2fa RENAME COLUMN login_uuid TO login_id;
ALTER TABLE public.password_reset_tokens RENAME COLUMN user_uuid TO user_id;
ALTER TABLE public.user_roles RENAME COLUMN user_uuid TO user_id;
ALTER TABLE public.user_roles RENAME COLUMN role_uuid TO role_id;
ALTER TABLE public.users RENAME COLUMN login_uuid TO login_id;

-- Add primary key constraints
ALTER TABLE public.login ADD CONSTRAINT login_id_unique UNIQUE (id);
ALTER TABLE public.roles ADD CONSTRAINT roles_pkey PRIMARY KEY (id);
ALTER TABLE public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);
ALTER TABLE public.backup_codes ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (id);
ALTER TABLE public.login_2fa ADD CONSTRAINT login_2fa_pkey PRIMARY KEY (id);
ALTER TABLE public.password_reset_tokens ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);
ALTER TABLE public.user_roles ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);

-- Add foreign key constraints
ALTER TABLE public.users ADD CONSTRAINT users_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES public.login(id);
ALTER TABLE public.user_roles ADD CONSTRAINT user_roles_role_id_fkey 
    FOREIGN KEY (role_id) REFERENCES public.roles(id);
ALTER TABLE public.user_roles ADD CONSTRAINT user_roles_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES public.users(id);
ALTER TABLE public.backup_codes ADD CONSTRAINT backup_codes_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES public.users(id);
ALTER TABLE public.login_2fa ADD CONSTRAINT login_2fa_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES public.login(id);
ALTER TABLE public.password_reset_tokens ADD CONSTRAINT password_reset_tokens_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES public.users(id);

-- Update sequence defaults
ALTER TABLE public.backup_codes ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.login ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.login_2fa ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.password_reset_tokens ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.roles ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.users ALTER COLUMN id SET DEFAULT gen_random_uuid();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop foreign key constraints first
ALTER TABLE public.backup_codes DROP CONSTRAINT IF EXISTS backup_codes_user_id_fkey CASCADE;
ALTER TABLE public.login_2fa DROP CONSTRAINT IF EXISTS login_2fa_login_id_fkey CASCADE;
ALTER TABLE public.password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_user_id_fkey CASCADE;
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_role_id_fkey CASCADE;
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_user_id_fkey CASCADE;
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_login_id_fkey CASCADE;

-- Drop primary key constraints
ALTER TABLE public.backup_codes DROP CONSTRAINT IF EXISTS backup_codes_pkey CASCADE;
ALTER TABLE public.login DROP CONSTRAINT IF EXISTS login_id_unique CASCADE;
ALTER TABLE public.login_2fa DROP CONSTRAINT IF EXISTS login_2fa_pkey CASCADE;
ALTER TABLE public.password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_pkey CASCADE;
ALTER TABLE public.roles DROP CONSTRAINT IF EXISTS roles_pkey CASCADE;
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_pkey CASCADE;
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey CASCADE;

-- Rename primary key columns back
ALTER TABLE public.backup_codes RENAME COLUMN id TO uuid;
ALTER TABLE public.login RENAME COLUMN id TO uuid;
ALTER TABLE public.login_2fa RENAME COLUMN id TO uuid;
ALTER TABLE public.password_reset_tokens RENAME COLUMN id TO uuid;
ALTER TABLE public.roles RENAME COLUMN id TO uuid;
ALTER TABLE public.users RENAME COLUMN id TO uuid;

-- Rename foreign key columns back
ALTER TABLE public.backup_codes RENAME COLUMN user_id TO user_uuid;
ALTER TABLE public.login_2fa RENAME COLUMN login_id TO login_uuid;
ALTER TABLE public.password_reset_tokens RENAME COLUMN user_id TO user_uuid;
ALTER TABLE public.user_roles RENAME COLUMN user_id TO user_uuid;
ALTER TABLE public.user_roles RENAME COLUMN role_id TO role_uuid;
ALTER TABLE public.users RENAME COLUMN login_id TO login_uuid;

-- Add primary key and unique constraints back
ALTER TABLE public.login ADD CONSTRAINT login_uuid_unique UNIQUE (uuid);
ALTER TABLE public.roles ADD CONSTRAINT roles_pkey PRIMARY KEY (uuid);
ALTER TABLE public.users ADD CONSTRAINT users_pkey PRIMARY KEY (uuid);
ALTER TABLE public.backup_codes ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (uuid);
ALTER TABLE public.login_2fa ADD CONSTRAINT login_2fa_pkey PRIMARY KEY (uuid);
ALTER TABLE public.password_reset_tokens ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (uuid);
ALTER TABLE public.user_roles ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_uuid, role_uuid);

-- Add foreign key constraints back
ALTER TABLE public.users ADD CONSTRAINT users_login_uuid_fkey 
    FOREIGN KEY (login_uuid) REFERENCES public.login(uuid);
ALTER TABLE public.user_roles ADD CONSTRAINT user_roles_role_uuid_fkey 
    FOREIGN KEY (role_uuid) REFERENCES public.roles(uuid);
ALTER TABLE public.user_roles ADD CONSTRAINT user_roles_user_uuid_fkey 
    FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);
ALTER TABLE public.backup_codes ADD CONSTRAINT backup_codes_user_uuid_fkey 
    FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);
ALTER TABLE public.login_2fa ADD CONSTRAINT login_2fa_login_uuid_fkey 
    FOREIGN KEY (login_uuid) REFERENCES public.login(uuid);
ALTER TABLE public.password_reset_tokens ADD CONSTRAINT password_reset_tokens_user_uuid_fkey 
    FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);

-- Update sequence defaults back
ALTER TABLE public.backup_codes ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE public.login ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE public.login_2fa ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE public.password_reset_tokens ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE public.roles ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE public.users ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
-- +goose StatementEnd
