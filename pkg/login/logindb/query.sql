-- name: FindUser :one
SELECT uuid, username, password
FROM login
WHERE username = $1
AND deleted_at IS NULL;

-- name: ResetPassword :exec
UPDATE login
SET password = $1, 
    last_modified_at = NOW()
WHERE username = $2; 

-- name: FindLoginByUsername :one
SELECT l.uuid, l.username, l.password, l.created_at, l.updated_at
FROM login l
WHERE l.username = $1
AND l.deleted_at IS NULL;

-- name: InitPasswordByUsername :one
SELECT uuid
FROM login
WHERE username = $1;

-- name: FindUsernameByEmail :one
SELECT u.username
FROM users u
WHERE u.email = $1
AND u.deleted_at IS NULL;

-- name: UpdateUserPassword :exec
UPDATE login
SET password = $1,
    updated_at = NOW()
WHERE uuid = $2;

-- name: FindUserRolesByUserUuid :many
SELECT r.name
FROM user_roles ur
LEFT JOIN roles r ON ur.role_uuid = r.uuid
WHERE ur.user_uuid = $1;

-- name: FindUserInfoWithRoles :one
SELECT u.email, u.username, u.name, COALESCE(array_agg(r.name), '{}') AS roles
FROM users u
LEFT JOIN user_roles ur ON u.uuid = ur.user_uuid
LEFT JOIN roles r ON ur.role_uuid = r.uuid
WHERE u.uuid = $1
AND u.deleted_at IS NULL
GROUP BY u.email, u.username, u.name;

-- name: InitPasswordResetToken :exec
INSERT INTO password_reset_tokens (user_uuid, token, expire_at)
VALUES ($1, $2, $3);

-- name: ValidatePasswordResetToken :one
SELECT prt.uuid as uuid, prt.user_uuid as user_uuid
FROM password_reset_tokens prt
JOIN users u ON u.uuid = prt.user_uuid 
WHERE prt.token = $1
  AND prt.expire_at > NOW()
  AND prt.used_at IS NULL
LIMIT 1;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE password_reset_tokens
SET used_at = NOW()
WHERE token = $1;

-- name: GetUsersByLoginUuid :many
SELECT u.uuid, u.username, u.name, u.email, u.created_at, u.last_modified_at,
       COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') as roles
FROM users u
LEFT JOIN user_roles ur ON u.uuid = ur.user_uuid
LEFT JOIN roles r ON ur.role_uuid = r.uuid
WHERE u.login_uuid = $1
AND u.deleted_at IS NULL
GROUP BY u.uuid, u.username, u.name, u.email, u.created_at, u.last_modified_at;

-- name: ResetPasswordByUuid :exec
UPDATE login
SET password = $1,
    updated_at = NOW()
WHERE login.uuid = $2;

-- name: Get2FASecret :one
SELECT two_factor_secret
FROM users
WHERE users.uuid = $1
AND deleted_at IS NULL;

-- name: Get2FAByLoginUuid :one
SELECT u.two_factor_secret
FROM users u
JOIN login l ON l.user_uuid = u.uuid
WHERE l.uuid = $1
AND u.deleted_at IS NULL;

-- name: ValidateBackupCode :one
SELECT EXISTS (
  SELECT 1
  FROM login l
  WHERE l.uuid = @uuid
  AND @code::text = ANY(l.two_factor_backup_codes)
  AND l.deleted_at IS NULL
) AS is_valid;

-- name: MarkBackupCodeUsed :exec
UPDATE login l
SET two_factor_backup_codes = array_remove(two_factor_backup_codes, @code::text)
WHERE l.uuid = @uuid
AND l.deleted_at IS NULL;

-- name: GetLoginByUUID :one
SELECT l.uuid as login_uuid, l.username, l.password, l.created_at, l.updated_at,
       l.two_factor_enabled, l.two_factor_secret, l.two_factor_backup_codes
FROM login l
WHERE l.uuid = $1
AND l.deleted_at IS NULL;