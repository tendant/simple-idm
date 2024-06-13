-- name: CreateUser :one
INSERT INTO users (email, name)
VALUES ($1, $2)
RETURNING *;


-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20;


-- name: UpdateUser :one
UPDATE users SET name = $2 WHERE uuid = $1
RETURNING *;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = CURRENT_TIMESTAMP
WHERE uuid = $1;

-- name: GetUserUUID :one
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
WHERE uuid = $1;
