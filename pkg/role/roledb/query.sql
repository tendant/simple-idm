-- name: FindRoles :many
SELECT id, name
FROM roles
ORDER BY name ASC;

-- name: CreateRole :one
INSERT INTO roles (name) VALUES ($1) RETURNING id;

-- name: UpdateRole :exec
UPDATE roles SET name = $2 WHERE id = $1;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1;

-- name: GetRoleById :one
SELECT id, name
FROM roles
WHERE id = $1;

-- name: HasUsers :one
SELECT EXISTS (
    SELECT 1 FROM user_roles WHERE role_id = $1
) as has_users;

-- name: GetRoleUsers :many
SELECT u.id, u.email, u.name
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
WHERE ur.role_id = $1
ORDER BY u.email;

-- name: RemoveUserFromRole :exec
DELETE FROM user_roles 
WHERE user_id = $1 AND role_id = $2;

-- name: CreateUserRole :one
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
RETURNING *;

-- name: GetRoleIdByName :one
SELECT id
FROM roles
WHERE name = $1;
