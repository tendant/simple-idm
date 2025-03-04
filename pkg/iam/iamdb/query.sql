-- name: CreateUser :one
INSERT INTO users (email, name)
VALUES ($1, $2)
RETURNING *;

-- name: CreateUserRole :one
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
RETURNING *;

-- name: CreateUserRoleBatch :copyfrom
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2);

-- name: FindUsers :many
SELECT id, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
WHERE deleted_at IS NULL
ORDER BY created_at ASC
limit 20;

-- name: UpdateUser :one
UPDATE users SET name = $2 WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = CURRENT_TIMESTAMP
WHERE id = $1;

-- name: GetUserById :one
SELECT id, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
WHERE id = $1;

-- name: DeleteUserRoles :exec
DELETE FROM user_roles
WHERE user_id = $1;

-- name: GetUserWithRoles :one
SELECT u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name,
       json_agg(json_build_object(
           'id', r.id,
           'name', r.name
       )) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1
GROUP BY u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name;

-- Role queries

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

-- name: FindUsersWithRoles :many
SELECT u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name,
       json_agg(json_build_object(
           'id', r.id,
           'name', r.name
       )) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.deleted_at IS NULL
GROUP BY u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name
ORDER BY u.created_at ASC
LIMIT 20;
