// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: query.sql

package loginsdb

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const countLogins = `-- name: CountLogins :one
SELECT COUNT(*) FROM login
WHERE deleted_at IS NULL
`

func (q *Queries) CountLogins(ctx context.Context) (int64, error) {
	row := q.db.QueryRow(ctx, countLogins)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const createLogin = `-- name: CreateLogin :one
INSERT INTO login (
  username,
  password,
  created_by
) VALUES (
  $1, $2, $3
)
RETURNING id, created_at, updated_at, deleted_at, created_by, password, username, password_version
`

type CreateLoginParams struct {
	Username  sql.NullString `json:"username"`
	Password  []byte         `json:"password"`
	CreatedBy sql.NullString `json:"created_by"`
}

func (q *Queries) CreateLogin(ctx context.Context, arg CreateLoginParams) (Login, error) {
	row := q.db.QueryRow(ctx, createLogin, arg.Username, arg.Password, arg.CreatedBy)
	var i Login
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Password,
		&i.Username,
		&i.PasswordVersion,
	)
	return i, err
}

const deleteLogin = `-- name: DeleteLogin :exec
UPDATE login
SET 
  deleted_at = (now() AT TIME ZONE 'utc')
WHERE id = $1
`

func (q *Queries) DeleteLogin(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, deleteLogin, id)
	return err
}

const getLogin = `-- name: GetLogin :one
SELECT id, created_at, updated_at, deleted_at, created_by, password, username, password_version FROM login
WHERE id = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetLogin(ctx context.Context, id uuid.UUID) (Login, error) {
	row := q.db.QueryRow(ctx, getLogin, id)
	var i Login
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Password,
		&i.Username,
		&i.PasswordVersion,
	)
	return i, err
}

const getLoginByUsername = `-- name: GetLoginByUsername :one
SELECT id, created_at, updated_at, deleted_at, created_by, password, username, password_version FROM login
WHERE username = $1 AND deleted_at IS NULL LIMIT 1
`

func (q *Queries) GetLoginByUsername(ctx context.Context, username sql.NullString) (Login, error) {
	row := q.db.QueryRow(ctx, getLoginByUsername, username)
	var i Login
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Password,
		&i.Username,
		&i.PasswordVersion,
	)
	return i, err
}

const listLogins = `-- name: ListLogins :many
SELECT id, created_at, updated_at, deleted_at, created_by, password, username, password_version FROM login
WHERE deleted_at IS NULL
ORDER BY username
LIMIT $1 OFFSET $2
`

type ListLoginsParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListLogins(ctx context.Context, arg ListLoginsParams) ([]Login, error) {
	rows, err := q.db.Query(ctx, listLogins, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Login
	for rows.Next() {
		var i Login
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
			&i.CreatedBy,
			&i.Password,
			&i.Username,
			&i.PasswordVersion,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const searchLogins = `-- name: SearchLogins :many
SELECT id, created_at, updated_at, deleted_at, created_by, password, username, password_version FROM login
WHERE 
  deleted_at IS NULL AND
  username ILIKE '%' || $1 || '%'
ORDER BY username
LIMIT $2 OFFSET $3
`

type SearchLoginsParams struct {
	Column1 pgtype.Text `json:"column_1"`
	Limit   int32       `json:"limit"`
	Offset  int32       `json:"offset"`
}

func (q *Queries) SearchLogins(ctx context.Context, arg SearchLoginsParams) ([]Login, error) {
	rows, err := q.db.Query(ctx, searchLogins, arg.Column1, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Login
	for rows.Next() {
		var i Login
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DeletedAt,
			&i.CreatedBy,
			&i.Password,
			&i.Username,
			&i.PasswordVersion,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateLogin = `-- name: UpdateLogin :one
UPDATE login
SET 
  username = $2,
  updated_at = (now() AT TIME ZONE 'utc')
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, created_at, updated_at, deleted_at, created_by, password, username, password_version
`

type UpdateLoginParams struct {
	ID       uuid.UUID      `json:"id"`
	Username sql.NullString `json:"username"`
}

func (q *Queries) UpdateLogin(ctx context.Context, arg UpdateLoginParams) (Login, error) {
	row := q.db.QueryRow(ctx, updateLogin, arg.ID, arg.Username)
	var i Login
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Password,
		&i.Username,
		&i.PasswordVersion,
	)
	return i, err
}
