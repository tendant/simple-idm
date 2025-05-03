-- +goose Up
-- +goose StatementBegin
ALTER TABLE device ADD COLUMN device_name VARCHAR(255);
ALTER TABLE device ADD COLUMN device_type VARCHAR(50);
ALTER TABLE login_device ADD COLUMN display_name VARCHAR(255);
ALTER TABLE login_device ADD COLUMN updated_at TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE login_device ADD COLUMN created_at TIMESTAMP WITHOUT TIME ZONE;

-- Set initial display_name based on device_name
UPDATE login_device ld
SET display_name = d.device_name
FROM device d
WHERE ld.fingerprint = d.fingerprint;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE device DROP COLUMN IF EXISTS device_name;
ALTER TABLE device DROP COLUMN IF EXISTS device_type;
ALTER TABLE login_device DROP COLUMN IF EXISTS display_name;
ALTER TABLE login_device DROP COLUMN IF EXISTS updated_at;
ALTER TABLE login_device DROP COLUMN IF EXISTS created_at;
-- +goose StatementEnd
