-- name: GetUserByUuid :one
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
WHERE uuid = $1;

-- name: FindUserRolesByUserUuid :many
SELECT name
FROM user_roles ur
LEFT JOIN roles ON ur.role_uuid = roles.uuid
WHERE ur.user_uuid = $1;