-- name: CreateUser :one
INSERT INTO users (email)
VALUES ($1)
RETURNING *;


-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email
FROM users
limit 20;


-- name: UpdateUser :one
UPDATE users SET email = $2 WHERE uuid = $1
RETURNING *;
