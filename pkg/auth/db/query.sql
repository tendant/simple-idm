-- name: FindUserByUserUuid :one
SELECT users.uuid, name, username, email, password
FROM users
WHERE uuid = $1;