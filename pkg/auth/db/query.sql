-- name: FindUserByUserUuid :one
SELECT users.uuid, name, username, email, password
FROM users
WHERE uuid = $1
AND deleted_at IS NULL;

-- name: UpdatePassowrd :exec
UPDATE users
SET password = $1, last_modified_at = $2
WHERE uuid = $3
AND deleted_at IS NULL;