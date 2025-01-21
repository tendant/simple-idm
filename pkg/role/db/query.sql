-- name: FindRoles :many
SELECT uuid, name
FROM roles
ORDER BY name ASC;
