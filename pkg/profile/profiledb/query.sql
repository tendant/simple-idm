-- name: UpdateUsername :exec
UPDATE users
SET username = $2,
    last_modified_at = NOW()
WHERE uuid = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password = $2,
    last_modified_at = NOW()
WHERE uuid = $1;  -- Verify current password

-- name: GetUserByUUID :one
SELECT uuid, username, email, password, created_at, last_modified_at
FROM users
WHERE uuid = $1;

-- name: FindUserByUsername :many
SELECT uuid, username, email, password, two_factor_secret, two_factor_enabled, two_factor_backup_codes, created_at, last_modified_at
FROM users
WHERE username = $1;

-- name: Disable2FA :exec
UPDATE users
SET two_factor_secret = NULL,
    two_factor_enabled = FALSE,
    two_factor_backup_codes = NULL,
    last_modified_at = NOW()
WHERE uuid = $1;

-- name: Enable2FA :exec
UPDATE users
SET two_factor_secret = $1::text,
    two_factor_enabled = TRUE,
    two_factor_backup_codes = $2::text[],
    last_modified_at = NOW()
WHERE uuid = $3;
