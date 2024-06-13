-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20;

-- name: InitPassword :one
SELECT uuid
FROM users
WHERE email = $1;

-- name: ResetPassword :exec
UPDATE users
SET password = $1, 
    last_modified_at = NOW()
WHERE email = $2;  
