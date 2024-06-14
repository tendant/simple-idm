-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20;

-- name: RegisterUser :one
INSERT INTO users (email, name, password, created_at)
VALUES ($1, $2, $3, NOW())
RETURNING *;

-- name: EmailVerify :exec
UPDATE users
SET verified_at = NOW()
WHERE email = $1;