-- name: UpdateUserPassword :exec
UPDATE users
SET password = $2,
    last_modified_at = NOW()
WHERE uuid = $1
  AND password = $1;  -- Verify current password

-- name: GetUserByUUID :one
SELECT uuid, username, email, name, created_at, last_modified_at
FROM users
WHERE uuid = $1;