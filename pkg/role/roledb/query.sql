-- name: FindRoles :many
SELECT uuid, name
FROM roles
ORDER BY name ASC;

-- name: CreateRole :exec
INSERT INTO roles (name) VALUES ($1) RETURNING uuid;

-- name: UpdateRole :exec
UPDATE roles SET name = $2 WHERE uuid = $1;

-- name: DeleteRole :exec
DELETE FROM roles WHERE uuid = $1;

-- name: GetRoleUUID :one
SELECT uuid, name
FROM roles
WHERE uuid = $1;