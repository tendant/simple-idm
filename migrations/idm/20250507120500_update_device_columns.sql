-- +goose Up
-- +goose StatementBegin
-- Make user_agent nullable
ALTER TABLE device ALTER COLUMN user_agent DROP NOT NULL;

-- Add device_id column (UUID, nullable)
ALTER TABLE device ADD COLUMN device_id UUID;

-- Create an index on device_id for better query performance
CREATE INDEX idx_device_device_id ON device(device_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Remove the index
DROP INDEX IF EXISTS idx_device_device_id;

-- Remove device_id column
ALTER TABLE device DROP COLUMN IF EXISTS device_id;

-- Make user_agent NOT NULL again
ALTER TABLE device ALTER COLUMN user_agent SET NOT NULL;
-- +goose StatementEnd
