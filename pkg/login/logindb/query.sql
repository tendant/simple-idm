-- name: FindUser :one
SELECT id, username, password
FROM login
WHERE username = $1
AND deleted_at IS NULL;

-- name: ResetPassword :exec
UPDATE login
SET password = $1, 
    last_modified_at = NOW()
WHERE username = $2; 

-- name: FindLoginByUsername :one
SELECT l.id, l.username, l.password, l.created_at, l.updated_at
FROM login l
WHERE l.username = $1
AND l.deleted_at IS NULL;

-- name: InitPasswordByUsername :one
SELECT id
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
WHERE id = $2;

-- name: FindUserRolesByUserId :many
SELECT r.name
FROM user_roles ur
LEFT JOIN roles r ON ur.role_id = r.id
WHERE ur.user_id = $1;

-- name: FindUserInfoWithRoles :one
SELECT u.email, u.username, u.name, COALESCE(array_agg(r.name), '{}') AS roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1
AND u.deleted_at IS NULL
GROUP BY u.email, u.username, u.name;

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
SELECT u.id, u.username, u.name, u.email, u.created_at, u.last_modified_at,
       COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.login_id = $1
AND u.deleted_at IS NULL
GROUP BY u.id, u.username, u.name, u.email, u.created_at, u.last_modified_at;

-- name: ResetPasswordById :exec
UPDATE login
SET password = $1,
    updated_at = NOW()
WHERE login.id = $2;

-- name: Get2FASecret :one
SELECT two_factor_secret
FROM users
WHERE users.id = $1
AND deleted_at IS NULL;

-- name: Get2FAByLoginId :one
SELECT u.two_factor_secret
FROM users u
JOIN login l ON l.user_id = u.id
WHERE l.id = $1
AND u.deleted_at IS NULL;

-- name: ValidateBackupCode :one
SELECT EXISTS (
  SELECT 1
  FROM login l
  WHERE l.id = @id
  AND @code::text = ANY(l.two_factor_backup_codes)
  AND l.deleted_at IS NULL
) AS is_valid;

-- name: MarkBackupCodeUsed :exec
UPDATE login l
SET two_factor_backup_codes = array_remove(two_factor_backup_codes, @code::text)
WHERE l.id = @id
AND l.deleted_at IS NULL;

-- name: GetLoginById :one
SELECT l.id as login_id, l.username, l.password, l.created_at, l.updated_at,
       l.two_factor_enabled, l.two_factor_secret, l.two_factor_backup_codes
FROM login l
WHERE l.id = $1
AND l.deleted_at IS NULL;

-- name: RegisterUser :one
WITH new_login AS (
  INSERT INTO login (username, password)
  VALUES (@username, @password)
  RETURNING id
)
INSERT INTO users (login_id, username, email, name)
SELECT nl.id, @username, @email, @name
FROM new_login nl
RETURNING id, username, email, name, created_at, last_modified_at, deleted_at;