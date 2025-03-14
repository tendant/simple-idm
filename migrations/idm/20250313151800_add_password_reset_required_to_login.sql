-- +goose Up
-- +goose StatementBegin
ALTER TABLE login ADD COLUMN IF NOT EXISTS password_reset_required BOOLEAN;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login DROP COLUMN IF EXISTS password_reset_required;
-- +goose StatementEnd