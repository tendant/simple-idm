-- name: FindUser :one
SELECT id, username, password, password_version
FROM login
WHERE username = $1
AND deleted_at IS NULL;

-- name: ResetPassword :exec
UPDATE login
SET password = $1, 
    last_modified_at = NOW()
WHERE username = $2; 

-- name: FindLoginByUsername :one
SELECT l.id, l.username, l.password, l.password_version, l.created_at, l.updated_at
FROM login l
WHERE l.username = $1
AND l.deleted_at IS NULL;

-- name: InitPasswordByUsername :one
SELECT id
FROM login
WHERE username = $1;

-- name: FindEmailByEmail :one
SELECT u.email
FROM users u
WHERE u.email = $1
AND u.deleted_at IS NULL;

-- name: UpdateUserPassword :exec
UPDATE login
SET password = $1,
    updated_at = NOW()
WHERE id = $2;

-- name: FindUserRolesByUserId :many
SELECT r.name
FROM user_roles ur
LEFT JOIN roles r ON ur.role_id = r.id
WHERE ur.user_id = $1;

-- name: FindUserInfoWithRoles :one
SELECT u.email, u.name, COALESCE(array_agg(r.name), '{}') AS roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1
AND u.deleted_at IS NULL
GROUP BY u.email, u.name;

-- name: InitPasswordResetToken :exec
INSERT INTO login_password_reset_tokens (login_id, token, expire_at)
VALUES ($1, $2, $3);

-- name: ValidatePasswordResetToken :one
SELECT prt.id as id, prt.login_id as login_id
FROM login_password_reset_tokens prt
JOIN login l ON l.id = prt.login_id 
WHERE prt.token = $1
  AND prt.expire_at > NOW()
  AND prt.used_at IS NULL
LIMIT 1;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE login_password_reset_tokens
SET used_at = NOW()
WHERE token = $1;

-- name: GetUsersByLoginId :many
SELECT u.id, u.name, u.email, u.created_at, u.last_modified_at,
       COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.login_id = $1
AND u.deleted_at IS NULL
GROUP BY u.id, u.name, u.email, u.created_at, u.last_modified_at;

-- name: ResetPasswordById :exec
UPDATE login
SET password = $1,
    updated_at = NOW()
WHERE login.id = $2;

-- name: Get2FASecret :one
-- This query is no longer valid as two_factor_secret has been removed
-- Keeping the query name for compatibility but returning NULL
SELECT NULL::text as two_factor_secret
FROM users
WHERE users.id = $1
AND deleted_at IS NULL;

-- name: Get2FAByLoginId :one
-- This query is no longer valid as two_factor_secret has been removed
-- Keeping the query name for compatibility but returning NULL
SELECT NULL::text as two_factor_secret
FROM users u
JOIN login l ON l.id = l.id -- Self-join as a placeholder
WHERE l.id = $1
AND u.deleted_at IS NULL
LIMIT 1;

-- name: ValidateBackupCode :one
-- This query is no longer valid as two_factor_backup_codes has been removed
-- Keeping the query name for compatibility but returning false
SELECT false AS is_valid;

-- name: MarkBackupCodeUsed :exec
-- This query is no longer valid as two_factor_backup_codes has been removed
-- Keeping the query name for compatibility but doing nothing
SELECT 1;

-- name: GetLoginById :one
SELECT l.id as login_id, l.username, l.password, l.created_at, l.updated_at
FROM login l
WHERE l.id = $1
AND l.deleted_at IS NULL;

-- name: UpdateUserPasswordAndVersion :exec
UPDATE login
SET password = $1,
    password_version = $3,
    updated_at = NOW()
WHERE id = $2;

-- name: AddPasswordToHistory :exec
INSERT INTO login_password_history (login_id, password_hash, password_version)
VALUES ($1, $2, $3);

-- name: GetPasswordHistory :many
SELECT id, login_id, password_hash, password_version, created_at
FROM login_password_history
WHERE login_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: GetUserPasswordVersion :one
SELECT password_version
FROM login
WHERE id = $1
AND deleted_at IS NULL;