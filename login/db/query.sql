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

-- name: InitPassword :one
SELECT uuid
FROM users
WHERE email = $1;

-- name: FindUser :one
SELECT uuid, name, email, password
FROM users
WHERE email = $1;
-- name: ResetPassword :exec
UPDATE users
SET password = $1, 
    last_modified_at = NOW()
WHERE email = $2; 
