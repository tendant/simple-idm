-- -- name: FindUsers :many
-- SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
-- FROM users
-- limit 20;

-- -- name: RegisterUser :one
-- INSERT INTO users (email, name, password, created_at)
-- VALUES ($1, $2, $3, NOW())
-- RETURNING *;

-- -- name: EmailVerify :exec
-- UPDATE users
-- SET verified_at = NOW()
-- WHERE email = $1;

-- -- name: InitPassword :one
-- SELECT uuid
-- FROM users
-- WHERE email = $1;

-- name: FindUser :one
SELECT uuid, username, password
FROM login
WHERE username = $1
AND deleted_at IS NULL;

-- name: ResetPassword :exec
UPDATE users
SET password = $1, 
    last_modified_at = NOW()
WHERE email = $2; 

-- name: FindLoginByUsername :one
SELECT l.uuid, l.username, l.password, l.created_at, l.updated_at
FROM login l
WHERE l.username = $1
AND l.deleted_at IS NULL
GROUP BY l.uuid, l.username, l.password, l.created_at, l.updated_at;

-- name: InitPasswordByUsername :one
SELECT uuid
FROM login
WHERE username = $1;

-- name: FindUsernameByEmail :one
SELECT username
FROM users
WHERE email = $1;

-- name: UpdateUserPassword :exec
UPDATE login
SET password = $1,
    last_modified_at = NOW()
WHERE uuid = $2;

-- name: FindUserRolesByUserUuid :many
SELECT name
FROM user_roles ur
LEFT JOIN roles ON ur.role_uuid = roles.uuid
WHERE ur.user_uuid = $1;

-- name: FindUserInfoWithRoles :one
SELECT l.email, l.username, l.name, COALESCE(array_agg(r.name), '{}') AS roles
FROM public.users l
LEFT JOIN public.user_roles ur ON l.uuid = ur.user_uuid
LEFT JOIN public.roles r ON ur.role_uuid = r.uuid
WHERE l.uuid = $1
GROUP BY l.email, l.username, l.name;

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
    last_modified_at = NOW()
WHERE uuid = $2;

-- name: Get2FASecret :one
SELECT two_factor_secret
FROM users
WHERE uuid = $1
AND deleted_at IS NULL;

-- name: ValidateBackupCode :one
SELECT EXISTS (
  SELECT 1
  FROM backup_codes
  WHERE user_uuid = $1
  AND code = $2
  AND used_at IS NULL
  AND deleted_at IS NULL
) AS is_valid;

-- name: MarkBackupCodeUsed :exec
UPDATE backup_codes
SET used_at = NOW()
WHERE user_uuid = $1
AND code = $2
AND used_at IS NULL;

-- name: GetUserByUUID :one
SELECT *
FROM users
WHERE uuid = $1
AND deleted_at IS NULL;