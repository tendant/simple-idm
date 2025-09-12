-- OAuth2 Client CRUD Operations

-- name: GetClient :one
SELECT 
    c.id, c.client_id, c.client_secret_encrypted, c.client_name, c.client_type,
    c.require_pkce, c.description, c.created_at, c.updated_at, c.created_by,
    COALESCE(array_agg(DISTINCT s.name) FILTER (WHERE s.name IS NOT NULL AND ocs.deleted_at IS NULL), '{}') as scopes,
    COALESCE(array_agg(DISTINCT uri.redirect_uri) FILTER (WHERE uri.redirect_uri IS NOT NULL AND uri.deleted_at IS NULL), '{}') as redirect_uris
FROM oauth2_clients c
LEFT JOIN oauth2_client_scopes ocs ON c.id = ocs.client_id AND ocs.deleted_at IS NULL
LEFT JOIN scopes s ON ocs.scope_id = s.id AND s.deleted_at IS NULL
LEFT JOIN oauth2_client_redirect_uris uri ON c.id = uri.client_id AND uri.deleted_at IS NULL
WHERE c.client_id = $1 AND c.deleted_at IS NULL
GROUP BY c.id, c.client_id, c.client_secret_encrypted, c.client_name, c.client_type,
         c.require_pkce, c.description, c.created_at, c.updated_at, c.created_by;

-- name: GetClientByID :one
SELECT 
    c.id, c.client_id, c.client_secret_encrypted, c.client_name, c.client_type,
    c.require_pkce, c.description, c.created_at, c.updated_at, c.created_by,
    COALESCE(array_agg(DISTINCT s.name) FILTER (WHERE s.name IS NOT NULL AND ocs.deleted_at IS NULL), '{}') as scopes,
    COALESCE(array_agg(DISTINCT uri.redirect_uri) FILTER (WHERE uri.redirect_uri IS NOT NULL AND uri.deleted_at IS NULL), '{}') as redirect_uris
FROM oauth2_clients c
LEFT JOIN oauth2_client_scopes ocs ON c.id = ocs.client_id AND ocs.deleted_at IS NULL
LEFT JOIN scopes s ON ocs.scope_id = s.id AND s.deleted_at IS NULL
LEFT JOIN oauth2_client_redirect_uris uri ON c.id = uri.client_id AND uri.deleted_at IS NULL
WHERE c.id = $1 AND c.deleted_at IS NULL
GROUP BY c.id, c.client_id, c.client_secret_encrypted, c.client_name, c.client_type,
         c.require_pkce, c.description, c.created_at, c.updated_at, c.created_by;

-- name: CreateClient :one
INSERT INTO oauth2_clients (
    client_id, client_secret_encrypted, client_name, client_type, 
    require_pkce, description, created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING id, created_at, updated_at;

-- name: UpdateClient :exec
UPDATE oauth2_clients 
SET client_secret_encrypted = $2, client_name = $3, client_type = $4,
    require_pkce = $5, description = $6, updated_at = NOW() AT TIME ZONE 'UTC'
WHERE client_id = $1 AND deleted_at IS NULL;

-- name: DeleteClient :exec
UPDATE oauth2_clients 
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE client_id = $1 AND deleted_at IS NULL;

-- name: ListClients :many
SELECT 
    c.id, c.client_id, c.client_secret_encrypted, c.client_name, c.client_type,
    c.require_pkce, c.description, c.created_at, c.updated_at, c.created_by,
    COALESCE(array_agg(DISTINCT s.name) FILTER (WHERE s.name IS NOT NULL AND ocs.deleted_at IS NULL), '{}') as scopes,
    COALESCE(array_agg(DISTINCT uri.redirect_uri) FILTER (WHERE uri.redirect_uri IS NOT NULL AND uri.deleted_at IS NULL), '{}') as redirect_uris
FROM oauth2_clients c
LEFT JOIN oauth2_client_scopes ocs ON c.id = ocs.client_id AND ocs.deleted_at IS NULL
LEFT JOIN scopes s ON ocs.scope_id = s.id AND s.deleted_at IS NULL
LEFT JOIN oauth2_client_redirect_uris uri ON c.id = uri.client_id AND uri.deleted_at IS NULL
WHERE c.deleted_at IS NULL
GROUP BY c.id, c.client_id, c.client_secret_encrypted, c.client_name, c.client_type,
         c.require_pkce, c.description, c.created_at, c.updated_at, c.created_by
ORDER BY c.created_at DESC;

-- name: ClientExists :one
SELECT EXISTS(
    SELECT 1 FROM oauth2_clients 
    WHERE client_id = $1 AND deleted_at IS NULL
);

-- name: GetClientCount :one
SELECT COUNT(*) FROM oauth2_clients WHERE deleted_at IS NULL;

-- Scope Operations

-- name: GetAllScopes :many
SELECT id, name, description, created_at, updated_at
FROM scopes 
WHERE deleted_at IS NULL
ORDER BY name;

-- Client-Scope Relationship Operations

-- name: AddClientScope :exec
INSERT INTO oauth2_client_scopes (client_id, scope_id)
VALUES ($1, $2)
ON CONFLICT (client_id, scope_id) DO UPDATE SET deleted_at = NULL;

-- name: RemoveClientScope :exec
UPDATE oauth2_client_scopes 
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE client_id = $1 AND scope_id = $2;

-- name: ClearClientScopes :exec
UPDATE oauth2_client_scopes 
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE client_id = $1;

-- Redirect URI Operations

-- name: AddClientRedirectURI :exec
INSERT INTO oauth2_client_redirect_uris (client_id, redirect_uri)
VALUES ($1, $2)
ON CONFLICT (client_id, redirect_uri) DO UPDATE SET deleted_at = NULL;

-- name: RemoveClientRedirectURI :exec
UPDATE oauth2_client_redirect_uris 
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE client_id = $1 AND redirect_uri = $2;

-- name: ClearClientRedirectURIs :exec
UPDATE oauth2_client_redirect_uris 
SET deleted_at = NOW() AT TIME ZONE 'UTC'
WHERE client_id = $1;
