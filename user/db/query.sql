-- name: CreateUser :one
INSERT INTO users (email)
VALUES ($1)
RETURNING *;


-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email
FROM users
limit 20;