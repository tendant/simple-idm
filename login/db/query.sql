-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20;

-- name: InitPassword :one
SELECT uuid
FROM users
WHERE email = $1;

-- name: FindUser :one
SELECT uuid, name, email, password
FROM users
WHERE email = $1;