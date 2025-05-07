-- Create admin user with password 'pwd'
-- This script runs when the PostgreSQL container is first initialized

-- First, ensure the uuid-ossp extension is available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Insert admin login with bcrypt-hashed password
-- The password 'pwd' is hashed using bcrypt with default cost
INSERT INTO bat.login (id, created_at, updated_at, created_by, password, username, password_version)
VALUES (
    gen_random_uuid(),
    now() AT TIME ZONE 'utc',
    now() AT TIME ZONE 'utc',
    'system',
    -- This is the bcrypt hash of 'pwd'
    '$2a$10$ukfkOO6WeRhn7YZxEh5O3.gfvDeypM1Dff.4LwU.tOGmyyGXPlnNC',
    'admin',
    1
)
ON CONFLICT DO NOTHING;

-- Create a role for admin if it doesn't exist
INSERT INTO bat.roles (id, name, description)
VALUES (
    gen_random_uuid(),
    'admin',
    'Administrator role with full system access'
)
ON CONFLICT DO NOTHING;

-- Create a user record linked to the login
WITH login_record AS (
    SELECT id FROM bat.login WHERE username = 'admin'
),
role_record AS (
    SELECT id FROM bat.roles WHERE name = 'admin'
)
INSERT INTO bat.users (id, created_at, last_modified_at, created_by, name, login_id, email)
SELECT
    gen_random_uuid(),
    now() AT TIME ZONE 'utc',
    now() AT TIME ZONE 'utc',
    'system',
    'Administrator',
    login_record.id,
    'admin@example.com'
FROM login_record
WHERE NOT EXISTS (
    SELECT 1 FROM bat.users WHERE login_id = login_record.id
);

-- Assign admin role to the user
WITH user_record AS (
    SELECT u.id as user_id
    FROM bat.users u
    JOIN bat.login l ON u.login_id = l.id
    WHERE l.username = 'admin'
),
role_record AS (
    SELECT id as role_id FROM bat.roles WHERE name = 'admin'
)
INSERT INTO bat.user_roles (user_id, role_id)
SELECT user_record.user_id, role_record.role_id
FROM user_record, role_record
ON CONFLICT (user_id, role_id) DO NOTHING;
