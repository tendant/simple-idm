-- +goose Up
-- +goose StatementBegin
ALTER TABLE users 
    DROP COLUMN password,
    DROP COLUMN verified_at,
    DROP COLUMN username,
    DROP COLUMN two_factor_secret,
    DROP COLUMN two_factor_enabled,
    DROP COLUMN two_factor_backup_codes;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users 
    ADD COLUMN password bytea,
    ADD COLUMN verified_at timestamp without time zone,
    ADD COLUMN username character varying(255),
    ADD COLUMN two_factor_secret text,
    ADD COLUMN two_factor_enabled boolean DEFAULT false,
    ADD COLUMN two_factor_backup_codes text[];
-- +goose StatementEnd
