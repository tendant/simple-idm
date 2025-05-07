-- name: FindUser :one
SELECT id, username, password, password_version
FROM login
WHERE username = $1
AND deleted_at IS NULL;

-- name: ResetPassword :exec
UPDATE login
SET password = $1, 
    last_modified_at = NOW() at time zone 'UTC'
WHERE username = $2; 

-- name: FindLoginByUsername :one
SELECT l.id, l.username, l.password, l.password_version, l.created_at, l.updated_at,
       l.failed_login_attempts, l.last_failed_attempt_at, l.locked_until, l.password_updated_at, l.password_expires_at
FROM login l
WHERE l.username = $1
AND l.deleted_at IS NULL;

-- name: InitPasswordByUsername :one
SELECT id
FROM login
WHERE username = $1;

-- name: UpdatePasswordResetRequired :exec
UPDATE login
SET password_reset_required = $2
WHERE id = $1;

-- name: FindEmailByEmail :one
SELECT u.email
FROM users u
WHERE u.email = $1
AND u.deleted_at IS NULL;

-- name: UpdateUserPassword :exec
UPDATE login
SET password = $1,
    updated_at = NOW() at time zone 'UTC'
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

-- name: ExpirePasswordResetToken :exec
UPDATE login_password_reset_tokens
SET expire_at = NOW() at time zone 'UTC'
WHERE login_id = $1
AND used_at IS NULL
AND expire_at > NOW() at time zone 'UTC';

-- name: ValidatePasswordResetToken :one
SELECT prt.id as id, prt.login_id as login_id
FROM login_password_reset_tokens prt
JOIN login l ON l.id = prt.login_id 
WHERE prt.token = $1
  AND prt.expire_at > NOW() at time zone 'UTC'
  AND prt.used_at IS NULL
LIMIT 1;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE login_password_reset_tokens
SET used_at = NOW() at time zone 'UTC'
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
    updated_at = NOW() at time zone 'UTC'
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
SELECT l.id as login_id, l.username, l.password, l.created_at, l.updated_at,
       l.failed_login_attempts, l.last_failed_attempt_at, l.locked_until
FROM login l
WHERE l.id = $1
AND l.deleted_at IS NULL;

-- name: GetLoginByUserId :one
SELECT l.id as login_id, l.username, l.password, l.created_at, l.updated_at,
       l.failed_login_attempts, l.last_failed_attempt_at, l.locked_until
FROM login l
JOIN users u ON l.id = u.login_id
WHERE u.id = $1
AND l.deleted_at IS NULL;

-- name: UpdateUserPasswordAndVersion :exec
UPDATE login
SET password = $1,
    password_version = $3,
    updated_at = NOW() at time zone 'UTC'
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

-- name: GetPasswordVersion :one
SELECT password_version
FROM login
WHERE id = $1
AND deleted_at IS NULL;

-- name: FindUsernameByEmail :one
SELECT l.username
FROM login l
JOIN users u ON u.login_id = l.id
WHERE u.email = $1
AND u.deleted_at IS NULL
LIMIT 1;

-- name: GetPasswordUpdatedAt :one
SELECT password_updated_at
FROM login
WHERE id = $1
AND deleted_at IS NULL;

-- name: GetPasswordExpiresAt :one
SELECT password_expires_at
FROM login
WHERE id = $1
AND deleted_at IS NULL;

-- name: UpdatePasswordTimestamps :exec
UPDATE login
SET password_updated_at = $2, password_expires_at = $3
WHERE id = $1;

-- name: RecordLoginAttempt :exec
INSERT INTO login_attempt (
    id,
    login_id,
    ip_address,
    user_agent,
    success,
    failure_reason,
    device_fingerprint
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
);

-- name: GetRecentFailedAttempts :one
SELECT COUNT(*) 
FROM login_attempt 
WHERE login_id = $1 
AND success = false 
AND created_at > $2;

-- name: IncrementFailedLoginAttempts :exec
UPDATE login
SET failed_login_attempts = failed_login_attempts + 1,
    last_failed_attempt_at = now() at time zone 'UTC'
WHERE id = $1;

-- name: LockAccount :exec
UPDATE login
SET locked_until = $2, 
    updated_at = now() at time zone 'UTC'
WHERE id = $1;

-- name: ResetFailedLoginAttempts :exec
UPDATE login
SET failed_login_attempts = 0,
    locked_until = NULL,
    updated_at = now() at time zone 'UTC'
WHERE id = $1;

-- name: IsAccountLocked :one
SELECT 
    CASE 
        WHEN locked_until IS NULL THEN false
        WHEN locked_until <= now() THEN false
        ELSE true
    END as is_locked
FROM login
WHERE id = $1;

-- name: GetFailedLoginAttempts :one
SELECT failed_login_attempts, last_failed_attempt_at, locked_until
FROM login
WHERE id = $1;