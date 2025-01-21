-- name: FindRoles :many
SELECT uuid, name
FROM roles
ORDER BY name ASC;

-- name: CreateRole :one
INSERT INTO roles (name) VALUES ($1) RETURNING uuid;

-- name: UpdateRole :exec
UPDATE roles SET name = $2 WHERE uuid = $1;

-- name: DeleteRole :exec
DELETE FROM roles WHERE uuid = $1;

-- name: GetRoleUUID :one
SELECT uuid, name
FROM roles
WHERE uuid = $1;

-- name: HasUsers :one
SELECT EXISTS (
    SELECT 1 FROM user_roles WHERE role_uuid = $1
) as has_users;

-- name: GetRoleUsers :many
SELECT u.uuid, u.email, u.name, u.username
FROM users u
JOIN user_roles ur ON ur.user_uuid = u.uuid
WHERE ur.role_uuid = $1
ORDER BY u.email;