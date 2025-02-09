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
SELECT u.uuid, u.username, u.password, u.email, u.name, u.created_at, u.last_modified_at,
       array_agg(r.name) as roles
FROM users u
LEFT JOIN user_roles ur ON u.uuid = ur.user_uuid
LEFT JOIN roles r ON ur.role_uuid = r.uuid
WHERE u.username = $1
GROUP BY u.uuid, u.username, u.password, u.email, u.name, u.created_at, u.last_modified_at;

-- name: InitPasswordByUsername :one
SELECT uuid
FROM users
WHERE username = $1;

-- name: FindUsernameByEmail :one
SELECT username
FROM users
WHERE email = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password = $1,
    last_modified_at = NOW()
WHERE uuid = $2;

-- name: FindUserRolesByUserUuid :many
SELECT name
FROM user_roles ur
LEFT JOIN roles ON ur.role_uuid = roles.uuid
WHERE ur.user_uuid = $1;

-- name: FindUserInfoWithRoles :one
SELECT u.email, u.username, u.name, COALESCE(array_agg(r.name), '{}') AS roles
FROM public.users u
LEFT JOIN public.user_roles ur ON u.uuid = ur.user_uuid
LEFT JOIN public.roles r ON ur.role_uuid = r.uuid
WHERE u.uuid = $1
GROUP BY u.email, u.username, u.name;

-- name: InitPasswordResetToken :exec
INSERT INTO password_reset_tokens (user_uuid, token, expire_at)
VALUES ($1, $2, $3);

-- name: ValidatePasswordResetToken :one
SELECT prt.uuid as uuid, prt.user_uuid as user_uuid, u.email as email
FROM password_reset_tokens prt
JOIN users u ON u.uuid = prt.user_uuid
WHERE prt.token = $1
  AND prt.expire_at > NOW()
  AND prt.used_at IS NULL
LIMIT 1;

-- name: MarkPasswordResetTokenUsed :exec
UPDATE password_reset_tokens
SET used_at = NOW()
WHERE token = $1;

-- name: ResetPasswordByUuid :exec
UPDATE users
SET password = $1,
    last_modified_at = NOW()
WHERE uuid = $2;