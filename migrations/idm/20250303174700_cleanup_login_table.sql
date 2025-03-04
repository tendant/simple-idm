-- +goose Up
-- +goose StatementBegin
ALTER TABLE login 
    DROP COLUMN two_factor_secret,
    DROP COLUMN two_factor_enabled,
    DROP COLUMN two_factor_backup_codes;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login 
    ADD COLUMN two_factor_secret text,
    ADD COLUMN two_factor_enabled boolean DEFAULT false,
    ADD COLUMN two_factor_backup_codes text[];
-- +goose StatementEnd
