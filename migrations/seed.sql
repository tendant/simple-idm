-- Create admin user with password 'pwd'
-- This script runs when the PostgreSQL container is first initialized

-- First, ensure the uuid-ossp extension is available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Insert admin login with bcrypt-hashed password
-- The password 'pwd' is hashed using bcrypt with default cost
INSERT INTO login (id, created_at, updated_at, created_by, password, username)
VALUES (
    gen_random_uuid(),
    now() AT TIME ZONE 'utc',
    now() AT TIME ZONE 'utc',
    'system',
    -- This is the bcrypt hash of 'pwd'
    '$2a$10$zXEBnvKYm.GuZqCvWlUmxOBY1n3UZClKDjSYbPY9jlVQyONNwMBQS',
    'admin'
)
ON CONFLICT (username) DO NOTHING;

-- Create a role for admin if it doesn't exist
INSERT INTO roles (id, created_at, updated_at, created_by, name, description)
VALUES (
    gen_random_uuid(),
    now() AT TIME ZONE 'utc',
    now() AT TIME ZONE 'utc',
    'system',
    'admin',
    'Administrator role with full system access'
)
ON CONFLICT (name) DO NOTHING;

-- Create a user record linked to the login
WITH login_record AS (
    SELECT id FROM login WHERE username = 'admin'
),
role_record AS (
    SELECT id FROM roles WHERE name = 'admin'
)
INSERT INTO users (id, created_at, updated_at, created_by, name, login_id)
SELECT
    gen_random_uuid(),
    now() AT TIME ZONE 'utc',
    now() AT TIME ZONE 'utc',
    'system',
    'Administrator',
    login_record.id
FROM login_record
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE login_id = login_record.id
);

-- Assign admin role to the user
WITH user_record AS (
    SELECT u.id as user_id
    FROM users u
    JOIN login l ON u.login_id = l.id
    WHERE l.username = 'admin'
),
role_record AS (
    SELECT id as role_id FROM roles WHERE name = 'admin'
)
INSERT INTO user_roles (user_id, role_id)
SELECT user_record.user_id, role_record.role_id
FROM user_record, role_record
ON CONFLICT (user_id, role_id) DO NOTHING;
