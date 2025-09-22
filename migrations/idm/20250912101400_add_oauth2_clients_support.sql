-- +goose Up
-- +goose StatementBegin
-- Migration: Add OAuth2 Clients Support
-- Date: 2025-09-12
-- Description: Add OAuth2 clients, scopes, and related tables with encryption support

-- Create scopes master table
CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    deleted_at TIMESTAMP NULL
);

-- Create main OAuth2 clients table
CREATE TABLE oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_encrypted TEXT NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(50) NOT NULL,
    require_pkce BOOLEAN NOT NULL DEFAULT true,
    description TEXT,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    created_by VARCHAR(255),
    deleted_at TIMESTAMP NULL
);

-- Create client-scope relationships with soft delete
CREATE TABLE oauth2_client_scopes (
    client_id UUID REFERENCES oauth2_clients(id),
    scope_id UUID REFERENCES scopes(id),
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    deleted_at TIMESTAMP NULL,
    PRIMARY KEY (client_id, scope_id)
);

-- Create redirect URIs with soft delete support
CREATE TABLE oauth2_client_redirect_uris (
    client_id UUID REFERENCES oauth2_clients(id),
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'UTC'),
    deleted_at TIMESTAMP NULL,
    PRIMARY KEY (client_id, redirect_uri)
);
-- Insert standard OAuth2/OIDC scopes
INSERT INTO scopes (name, description) VALUES
('openid', 'OpenID Connect authentication'),
('profile', 'Access to user profile information'),
('email', 'Access to user email address'),
('groups', 'Access to user groups');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop tables in reverse order
DROP TABLE IF EXISTS oauth2_client_redirect_uris;
DROP TABLE IF EXISTS oauth2_client_scopes;
DROP TABLE IF EXISTS oauth2_clients;
DROP TABLE IF EXISTS scopes;
-- +goose StatementEnd
