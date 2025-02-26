-- +goose Up
-- +goose StatementBegin
-- Drop foreign key constraints first
ALTER TABLE backup_codes DROP CONSTRAINT IF EXISTS backup_codes_user_uuid_fkey CASCADE;
ALTER TABLE login_2fa DROP CONSTRAINT IF EXISTS login_2fa_login_uuid_fkey CASCADE;
ALTER TABLE password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_user_uuid_fkey CASCADE;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_role_uuid_fkey CASCADE;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_user_uuid_fkey CASCADE;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_login_uuid_fkey CASCADE;

-- Drop primary key and unique constraints
ALTER TABLE backup_codes DROP CONSTRAINT IF EXISTS backup_codes_pkey CASCADE;
ALTER TABLE login DROP CONSTRAINT IF EXISTS login_uuid_unique CASCADE;
ALTER TABLE login_2fa DROP CONSTRAINT IF EXISTS login_2fa_pkey CASCADE;
ALTER TABLE password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_pkey CASCADE;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_pkey CASCADE;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_pkey CASCADE;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey CASCADE;

-- Rename primary key columns
ALTER TABLE backup_codes RENAME COLUMN uuid TO id;
ALTER TABLE login RENAME COLUMN uuid TO id;
ALTER TABLE login_2fa RENAME COLUMN uuid TO id;
ALTER TABLE password_reset_tokens RENAME COLUMN uuid TO id;
ALTER TABLE roles RENAME COLUMN uuid TO id;
ALTER TABLE users RENAME COLUMN uuid TO id;

-- Rename foreign key columns
ALTER TABLE backup_codes RENAME COLUMN user_uuid TO user_id;
ALTER TABLE login_2fa RENAME COLUMN login_uuid TO login_id;
ALTER TABLE password_reset_tokens RENAME COLUMN user_uuid TO user_id;
ALTER TABLE user_roles RENAME COLUMN user_uuid TO user_id;
ALTER TABLE user_roles RENAME COLUMN role_uuid TO role_id;
ALTER TABLE users RENAME COLUMN login_uuid TO login_id;

-- Add primary key constraints
ALTER TABLE login ADD CONSTRAINT login_id_unique UNIQUE (id);
ALTER TABLE roles ADD CONSTRAINT roles_pkey PRIMARY KEY (id);
ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY (id);
ALTER TABLE backup_codes ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (id);
ALTER TABLE login_2fa ADD CONSTRAINT login_2fa_pkey PRIMARY KEY (id);
ALTER TABLE password_reset_tokens ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);
ALTER TABLE user_roles ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);

-- Add foreign key constraints
ALTER TABLE users ADD CONSTRAINT users_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES login(id);
ALTER TABLE user_roles ADD CONSTRAINT user_roles_role_id_fkey 
    FOREIGN KEY (role_id) REFERENCES roles(id);
ALTER TABLE user_roles ADD CONSTRAINT user_roles_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE backup_codes ADD CONSTRAINT backup_codes_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE login_2fa ADD CONSTRAINT login_2fa_login_id_fkey 
    FOREIGN KEY (login_id) REFERENCES login(id);
ALTER TABLE password_reset_tokens ADD CONSTRAINT password_reset_tokens_user_id_fkey 
    FOREIGN KEY (user_id) REFERENCES users(id);

-- Update sequence defaults
ALTER TABLE backup_codes ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE login ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE login_2fa ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE password_reset_tokens ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE roles ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop foreign key constraints first
ALTER TABLE backup_codes DROP CONSTRAINT IF EXISTS backup_codes_user_id_fkey CASCADE;
ALTER TABLE login_2fa DROP CONSTRAINT IF EXISTS login_2fa_login_id_fkey CASCADE;
ALTER TABLE password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_user_id_fkey CASCADE;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_role_id_fkey CASCADE;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_user_id_fkey CASCADE;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_login_id_fkey CASCADE;

-- Drop primary key constraints
ALTER TABLE backup_codes DROP CONSTRAINT IF EXISTS backup_codes_pkey CASCADE;
ALTER TABLE login DROP CONSTRAINT IF EXISTS login_id_unique CASCADE;
ALTER TABLE login_2fa DROP CONSTRAINT IF EXISTS login_2fa_pkey CASCADE;
ALTER TABLE password_reset_tokens DROP CONSTRAINT IF EXISTS password_reset_tokens_pkey CASCADE;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_pkey CASCADE;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_pkey CASCADE;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey CASCADE;

-- Rename primary key columns back
ALTER TABLE backup_codes RENAME COLUMN id TO uuid;
ALTER TABLE login RENAME COLUMN id TO uuid;
ALTER TABLE login_2fa RENAME COLUMN id TO uuid;
ALTER TABLE password_reset_tokens RENAME COLUMN id TO uuid;
ALTER TABLE roles RENAME COLUMN id TO uuid;
ALTER TABLE users RENAME COLUMN id TO uuid;

-- Rename foreign key columns back
ALTER TABLE backup_codes RENAME COLUMN user_id TO user_uuid;
ALTER TABLE login_2fa RENAME COLUMN login_id TO login_uuid;
ALTER TABLE password_reset_tokens RENAME COLUMN user_id TO user_uuid;
ALTER TABLE user_roles RENAME COLUMN user_id TO user_uuid;
ALTER TABLE user_roles RENAME COLUMN role_id TO role_uuid;
ALTER TABLE users RENAME COLUMN login_id TO login_uuid;

-- Add primary key and unique constraints back
ALTER TABLE login ADD CONSTRAINT login_uuid_unique UNIQUE (uuid);
ALTER TABLE roles ADD CONSTRAINT roles_pkey PRIMARY KEY (uuid);
ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY (uuid);
ALTER TABLE backup_codes ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (uuid);
ALTER TABLE login_2fa ADD CONSTRAINT login_2fa_pkey PRIMARY KEY (uuid);
ALTER TABLE password_reset_tokens ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (uuid);
ALTER TABLE user_roles ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_uuid, role_uuid);

-- Add foreign key constraints back
ALTER TABLE users ADD CONSTRAINT users_login_uuid_fkey 
    FOREIGN KEY (login_uuid) REFERENCES login(uuid);
ALTER TABLE user_roles ADD CONSTRAINT user_roles_role_uuid_fkey 
    FOREIGN KEY (role_uuid) REFERENCES roles(uuid);
ALTER TABLE user_roles ADD CONSTRAINT user_roles_user_uuid_fkey 
    FOREIGN KEY (user_uuid) REFERENCES users(uuid);
ALTER TABLE backup_codes ADD CONSTRAINT backup_codes_user_uuid_fkey 
    FOREIGN KEY (user_uuid) REFERENCES users(uuid);
ALTER TABLE login_2fa ADD CONSTRAINT login_2fa_login_uuid_fkey 
    FOREIGN KEY (login_uuid) REFERENCES login(uuid);
ALTER TABLE password_reset_tokens ADD CONSTRAINT password_reset_tokens_user_uuid_fkey 
    FOREIGN KEY (user_uuid) REFERENCES users(uuid);

-- Update sequence defaults back
ALTER TABLE backup_codes ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE login ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE login_2fa ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE password_reset_tokens ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE roles ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
ALTER TABLE users ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
-- +goose StatementEnd
