-- +goose Up
ALTER TABLE users
ADD PRIMARY KEY (uuid);


-- +goose Down
