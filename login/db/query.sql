-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20;