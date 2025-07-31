-- name: GetUserById :one
SELECT u.id, u.email, u.created_at, u.last_modified_at, u.login_id, l.username, l.password
FROM users u JOIN login l ON u.login_id = l.id
WHERE u.id = $1;

-- name: GetLoginById :one
SELECT id, username
FROM login
WHERE id = $1
AND deleted_at IS NULL;

-- name: Disable2FAByLoginId :exec
UPDATE login_2fa
SET deleted_at = now() AT TIME ZONE 'utc'
WHERE login_id = $1
AND deleted_at IS NULL;

-- name: Create2FAInit :one
INSERT INTO login_2fa (login_id, two_factor_secret, two_factor_enabled, two_factor_backup_codes)
VALUES ($1, $2, FALSE, $3::TEXT[])
RETURNING id;

-- name: Enable2FAByLoginId :exec
UPDATE login_2fa
SET two_factor_secret = $1::text,
    two_factor_enabled = TRUE,
    two_factor_backup_codes = $2::text[],
    last_modified_at = NOW() at time zone 'utc'
WHERE login_id = $3
AND deleted_at IS NULL;

-- name: UpdateUsername :exec
UPDATE login
SET username = $2,
    updated_at = NOW() at time zone 'utc'
WHERE id = $1;

-- name: FindUserByUsername :many
SELECT id, username
FROM login
WHERE username = $1
AND deleted_at Is NULL;

-- name: UpdateUserLoginId :one
UPDATE users
SET login_id = $2,
    last_modified_at = NOW() at time zone 'utc'
WHERE id = $1
RETURNING login_id;

-- name: UpdateUserPhone :exec
UPDATE users
SET phone = $2,
    last_modified_at = NOW() at time zone 'utc'
WHERE id = $1;

-- name: UpdateUserPassword :exec
-- UPDATE users
-- SET password = $2,
--     last_modified_at = NOW()
-- WHERE id = $1;  -- Verify current password


-- name: Disable2FA :exec
-- UPDATE users
-- SET two_factor_secret = NULL,
--     two_factor_enabled = FALSE,
--     two_factor_backup_codes = NULL,
--     last_modified_at = NOW()
-- WHERE id = $1;

-- name: Enable2FA :exec
-- UPDATE users
-- SET two_factor_secret = $1::text,
--     two_factor_enabled = TRUE,
--     two_factor_backup_codes = $2::text[],
--     last_modified_at = NOW()
-- WHERE id = $3;

-- name: GetLoginIDByUserID :one
-- SELECT l.id
-- FROM login l
-- JOIN users u ON l.id = u.login_id
-- WHERE u.id = $1
-- AND l.deleted_at IS NULL;
