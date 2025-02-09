-- name: CreateUser :one
INSERT INTO users (email, username, name)
VALUES ($1, $2, $3)
RETURNING *;

-- name: CreateUserRole :one
INSERT INTO user_roles (user_uuid, role_uuid)
VALUES ($1, $2)
RETURNING *;

-- name: CreateUserRoleBatch :copyfrom
INSERT INTO user_roles (user_uuid, role_uuid)
VALUES ($1, $2);

-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, username, name
FROM users
WHERE deleted_at IS NULL
ORDER BY created_at ASC
limit 20;

-- name: UpdateUser :one
UPDATE users SET name = $2 WHERE uuid = $1
RETURNING *;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = CURRENT_TIMESTAMP
WHERE uuid = $1;

-- name: GetUserUUID :one
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, username, name
FROM users
WHERE uuid = $1;

-- name: DeleteUserRoles :exec
DELETE FROM user_roles
WHERE user_uuid = $1;

-- name: GetUserWithRoles :one
SELECT u.uuid, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.username, u.name,
       json_agg(json_build_object(
           'uuid', r.uuid,
           'name', r.name
       )) as roles
FROM users u
LEFT JOIN user_roles ur ON u.uuid = ur.user_uuid
LEFT JOIN roles r ON ur.role_uuid = r.uuid
WHERE u.uuid = $1
GROUP BY u.uuid, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.username, u.name;

-- name: FindUsersWithRoles :many
SELECT u.uuid, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.username, u.name,
       json_agg(json_build_object(
           'uuid', r.uuid,
           'name', r.name
       )) as roles
FROM users u
LEFT JOIN user_roles ur ON u.uuid = ur.user_uuid
LEFT JOIN roles r ON ur.role_uuid = r.uuid
WHERE u.deleted_at IS NULL
GROUP BY u.uuid, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.username, u.name
ORDER BY u.created_at ASC
LIMIT 20;

-- name: CreateRole :one
INSERT INTO roles (uuid, name)
VALUES ($1, $2)
RETURNING *;
