-- name: CreateVerificationToken :one
INSERT INTO email_verification_tokens (user_id, token, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetVerificationTokenByToken :one
SELECT id, user_id, token, created_at, expires_at, verified_at, deleted_at
FROM email_verification_tokens
WHERE token = $1
AND deleted_at IS NULL
AND verified_at IS NULL;

-- name: GetActiveTokensByUserId :many
SELECT id, user_id, token, created_at, expires_at, verified_at, deleted_at
FROM email_verification_tokens
WHERE user_id = $1
AND deleted_at IS NULL
AND verified_at IS NULL
AND expires_at > NOW() AT TIME ZONE 'UTC'
ORDER BY created_at DESC;

-- name: MarkTokenAsVerified :exec
UPDATE email_verification_tokens
SET verified_at = NOW() AT TIME ZONE 'UTC'
WHERE id = $1;

-- name: SoftDeleteToken :exec
UPDATE email_verification_tokens
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE id = $1;

-- name: SoftDeleteUserTokens :exec
UPDATE email_verification_tokens
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE user_id = $1
AND deleted_at IS NULL;

-- name: MarkUserEmailAsVerified :exec
UPDATE users
SET email_verified = TRUE,
    email_verified_at = NOW() AT TIME ZONE 'UTC'
WHERE id = $1;

-- name: GetUserEmailVerificationStatus :one
SELECT id, email, email_verified, email_verified_at
FROM users
WHERE id = $1
AND deleted_at IS NULL;

-- name: CountRecentTokensByUserId :one
SELECT COUNT(*)
FROM email_verification_tokens
WHERE user_id = $1
AND created_at > $2
AND deleted_at IS NULL;

-- name: CleanupExpiredTokens :exec
UPDATE email_verification_tokens
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE expires_at < NOW() AT TIME ZONE 'UTC'
AND deleted_at IS NULL
AND verified_at IS NULL;

-- name: GetUserByEmail :one
SELECT id, email, email_verified, email_verified_at, name, deleted_at
FROM users
WHERE email = $1
AND deleted_at IS NULL;
