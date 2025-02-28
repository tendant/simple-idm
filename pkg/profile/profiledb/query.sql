-- name: UpdateUsername :exec
UPDATE users
SET username = $2,
    last_modified_at = NOW()
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password = $2,
    last_modified_at = NOW()
WHERE id = $1;  -- Verify current password

-- name: GetUserById :one
SELECT id, username, email, password, created_at, last_modified_at
FROM users
WHERE id = $1;

-- name: FindUserByUsername :many
SELECT id, username, email, password, two_factor_secret, two_factor_enabled, two_factor_backup_codes, created_at, last_modified_at
FROM users
WHERE username = $1;

-- name: Disable2FA :exec
UPDATE users
SET two_factor_secret = NULL,
    two_factor_enabled = FALSE,
    two_factor_backup_codes = NULL,
    last_modified_at = NOW()
WHERE id = $1;

-- name: Disable2FAByLoginId :exec
UPDATE login_2fa
SET deleted_at = now() AT TIME ZONE 'utc'
WHERE login_id = $1
AND deleted_at IS NULL;

-- name: Create2FAInit :one
INSERT INTO login_2fa (login_id, two_factor_secret, two_factor_enabled, two_factor_backup_codes)
VALUES ($1, $2, FALSE, $3::TEXT[])
RETURNING id;

-- name: Enable2FA :exec
UPDATE users
SET two_factor_secret = $1::text,
    two_factor_enabled = TRUE,
    two_factor_backup_codes = $2::text[],
    last_modified_at = NOW()
WHERE id = $3;

-- name: Enable2FAByLoginId :exec
UPDATE login_2fa
SET two_factor_secret = $1::text,
    two_factor_enabled = TRUE,
    two_factor_backup_codes = $2::text[],
    last_modified_at = NOW()
WHERE login_id = $3
AND deleted_at IS NULL;

-- name: GetLoginIDByUserID :one
SELECT l.id
FROM login l
JOIN users u ON l.id = u.login_id
WHERE u.id = $1
AND l.deleted_at IS NULL;
