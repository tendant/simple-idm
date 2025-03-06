-- name: GetLogin :one
SELECT * FROM login
WHERE id = $1 AND deleted_at IS NULL LIMIT 1;

-- name: GetLoginByUsername :one
SELECT * FROM login
WHERE username = $1 AND deleted_at IS NULL LIMIT 1;

-- name: ListLogins :many
SELECT * FROM login
WHERE deleted_at IS NULL
ORDER BY username
LIMIT $1 OFFSET $2;

-- name: CreateLogin :one
INSERT INTO login (
  username,
  password,
  created_by
) VALUES (
  $1, $2, $3
)
RETURNING *;

-- name: UpdateLogin :one
UPDATE login
SET 
  username = $2,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DeleteLogin :exec
UPDATE login
SET 
  deleted_at = (now() AT TIME ZONE 'utc')
WHERE id = $1;

-- name: CountLogins :one
SELECT COUNT(*) FROM login
WHERE deleted_at IS NULL;

-- name: SearchLogins :many
SELECT * FROM login
WHERE 
  deleted_at IS NULL AND
  username ILIKE '%' || $1 || '%'
ORDER BY username
LIMIT $2 OFFSET $3;
