-- name: CreateUser :one
INSERT INTO users (email, name, login_id)
VALUES ($1, $2, $3)
RETURNING *;

-- name: CreateUserRole :one
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
RETURNING *;

-- name: CreateUserRoleBatch :copyfrom
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2);

-- name: FindUsers :many
SELECT u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name, u.login_id, l.username
FROM users u
JOIN login l ON u.login_id = l.id
WHERE u.deleted_at IS NULL
ORDER BY u.created_at ASC
limit 50;

-- name: UpdateUser :one
UPDATE users SET name = $2 WHERE id = $1
RETURNING *;

-- name: UpdateUserLoginID :one
UPDATE users SET login_id = $2 WHERE id = $1
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
       )) as roles,
       l.username,
       u.login_id
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
LEFT JOIN login l ON u.login_id = l.id
WHERE u.id = $1
GROUP BY u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name, l.username, u.login_id;

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
       )) as roles,
       l.username,
       u.login_id
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
LEFT JOIN login l ON u.login_id = l.id
WHERE u.deleted_at IS NULL
GROUP BY u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name, l.username, u.login_id
ORDER BY u.created_at ASC
LIMIT 50;

-- name: AnyUserExists :one
SELECT EXISTS (
    SELECT 1 FROM users
) as exists;

-- Group queries

-- name: CreateGroup :one
INSERT INTO groups (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: FindGroups :many
SELECT id, created_at, updated_at, name, description
FROM groups
WHERE deleted_at IS NULL
ORDER BY name ASC;

-- name: GetGroupById :one
SELECT id, created_at, updated_at, deleted_at, name, description
FROM groups
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateGroup :one
UPDATE groups 
SET name = $2, description = $3, updated_at = NOW() at time zone 'UTC'
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DeleteGroup :exec
UPDATE groups
SET deleted_at = NOW() at time zone 'UTC'
WHERE id = $1;


-- name: FindGroupUsers :many
SELECT u.id, u.email, u.name
FROM users u
JOIN user_groups ug ON ug.user_id = u.id
WHERE ug.group_id = $1 
AND u.deleted_at IS NULL
AND ug.deleted_at IS NULL
ORDER BY u.email;

-- name: CreateUserGroup :one
INSERT INTO user_groups (user_id, group_id)
VALUES ($1, $2)
RETURNING *;

-- name: UpsertUserGroup :one
INSERT INTO user_groups (user_id, group_id, assigned_at)
VALUES ($1, $2, NOW() AT TIME ZONE 'UTC')
ON CONFLICT (user_id, group_id) 
DO UPDATE SET 
    deleted_at = NULL,
    assigned_at = NOW() AT TIME ZONE 'UTC'
RETURNING *;

-- name: DeleteUserGroup :exec
UPDATE user_groups
SET deleted_at = NOW() at time zone 'UTC'
WHERE user_id = $1 AND group_id = $2;
