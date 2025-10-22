-- +goose Up
-- +goose StatementBegin
ALTER TABLE login_attempt ALTER COLUMN login_id DROP NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE login_attempt ALTER COLUMN login_id SET NOT NULL;


-- +goose StatementEnd