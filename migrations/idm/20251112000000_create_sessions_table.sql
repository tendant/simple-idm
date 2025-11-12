-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login_id UUID NOT NULL REFERENCES login(id) ON DELETE CASCADE,
    jti VARCHAR(255) NOT NULL UNIQUE, -- JWT ID for token identification
    token_type VARCHAR(20) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    issued_at TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    ip_address VARCHAR(45), -- Supports both IPv4 and IPv6
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    last_activity TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
    created_at TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    updated_at TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

-- Indexes for performance
CREATE INDEX idx_sessions_login_id ON sessions(login_id);
CREATE INDEX idx_sessions_jti ON sessions(jti);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_revoked_at ON sessions(revoked_at);
CREATE INDEX idx_sessions_token_type ON sessions(token_type);

-- Composite index for common query patterns
CREATE INDEX idx_sessions_login_active ON sessions(login_id, revoked_at, expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_sessions_login_active;
DROP INDEX IF EXISTS idx_sessions_token_type;
DROP INDEX IF EXISTS idx_sessions_revoked_at;
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_jti;
DROP INDEX IF EXISTS idx_sessions_login_id;
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd
