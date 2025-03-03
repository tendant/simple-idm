-- name: GetLogin :one
SELECT * FROM login
WHERE id = $1 AND deleted_at IS NULL LIMIT 1;

-- name: GetLoginByUsername :one
SELECT * FROM login
WHERE username = $1 AND deleted_at IS NULL LIMIT 1;

-- name: ListLogins :many
SELECT * FROM login
WHERE deleted_at IS NULL
ORDER BY username
LIMIT $1 OFFSET $2;

-- name: CreateLogin :one
INSERT INTO login (
  username,
  password,
  created_by
) VALUES (
  $1, $2, $3
)
RETURNING *;

-- name: UpdateLogin :one
UPDATE login
SET 
  username = $2,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DeleteLogin :exec
UPDATE login
SET 
  deleted_at = (now() AT TIME ZONE 'utc')
WHERE id = $1;

-- name: UpdateLoginPassword :one
UPDATE login
SET 
  password = $2,
  password_version = password_version + 1,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: EnableTwoFactor :one
UPDATE login
SET 
  two_factor_secret = $2,
  two_factor_enabled = true,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DisableTwoFactor :one
UPDATE login
SET 
  two_factor_enabled = false,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: SetTwoFactorBackupCodes :one
UPDATE login
SET 
  two_factor_backup_codes = $2,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: CountLogins :one
SELECT COUNT(*) FROM login
WHERE deleted_at IS NULL;

-- name: SearchLogins :many
SELECT * FROM login
WHERE 
  deleted_at IS NULL AND
  username ILIKE '%' || $1 || '%'
ORDER BY username
LIMIT $2 OFFSET $3;
