-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20;

-- name: RegisterUser :one
INSERT INTO users (email, name, password, created_at)
VALUES ($1, $2, $3, NOW())
RETURNING *;

-- name: EmailVerify :exec
UPDATE users
SET verified_at = NOW()
WHERE email = $1;

-- name: InitPassword :one
SELECT uuid
FROM users
WHERE email = $1;

-- name: FindUser :one
SELECT uuid, name, email, password
FROM users
WHERE email = $1;

-- name: ResetPassword :exec
UPDATE users
SET password = $1, 
    last_modified_at = NOW()
WHERE email = $2; 

-- name: FindUserByUsername :many
SELECT users.uuid, name, username, email, password, role_name
FROM users
LEFT JOIN user_roles ur ON users.uuid = ur.user_uuid
LEFT JOIN roles ON roles.uuid = ur.role_uuid
WHERE username = $1;

-- name: FindUserRolesByUserUuid :many
SELECT uuid, role_name, description
FROM user_roles ur
LEFT JOIN roles ON ur.role_uuid = roles.uuid
WHERE ur.user_uuid = $1;