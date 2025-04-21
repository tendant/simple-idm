-- name: GetUsersByLoginId :many
SELECT u.id, u.name, u.email, u.created_at, u.last_modified_at,
       COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.login_id = $1
AND u.deleted_at IS NULL
GROUP BY u.id, u.name, u.email, u.created_at, u.last_modified_at;


-- name: GetUserById :one
SELECT u.id, u.name, u.email, u.created_at, u.last_modified_at,
       COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') as roles, u.login_id
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1
AND u.deleted_at IS NULL
GROUP BY u.id, u.name, u.email, u.created_at, u.last_modified_at, u.login_id;


-- name: FindUsernamesByEmail :many
SELECT l.username
FROM login l
JOIN users u ON l.id = u.login_id
WHERE u.email = $1
AND l.deleted_at IS NULL;