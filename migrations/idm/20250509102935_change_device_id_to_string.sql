-- +goose Up
-- +goose StatementBegin
-- First, drop the index on the UUID column
DROP INDEX IF EXISTS idx_device_device_id;

-- Convert the device_id column from UUID to VARCHAR
ALTER TABLE device ALTER COLUMN device_id TYPE VARCHAR(255) USING device_id::text;

-- Create an index on the string device_id for better query performance
CREATE INDEX idx_device_device_id ON device(device_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop the index on the string column
DROP INDEX IF EXISTS idx_device_device_id;

-- Convert valid UUID strings back to UUID type
ALTER TABLE device ALTER COLUMN device_id TYPE UUID USING CASE 
  WHEN device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN device_id::uuid 
  ELSE NULL 
END;

-- Recreate the index on the UUID column
CREATE INDEX idx_device_device_id ON device(device_id);
-- +goose StatementEnd
