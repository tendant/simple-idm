// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const emailVerify = `-- name: EmailVerify :exec
UPDATE users
SET verified_at = NOW()
WHERE email = $1
`

func (q *Queries) EmailVerify(ctx context.Context, email string) error {
	_, err := q.db.Exec(ctx, emailVerify, email)
	return err
}

const findUsers = `-- name: FindUsers :many
SELECT uuid, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
limit 20
`

type FindUsersRow struct {
	Uuid           uuid.UUID      `json:"uuid"`
	CreatedAt      time.Time      `json:"created_at"`
	LastModifiedAt time.Time      `json:"last_modified_at"`
	DeletedAt      sql.NullTime   `json:"deleted_at"`
	CreatedBy      sql.NullString `json:"created_by"`
	Email          string         `json:"email"`
	Name           sql.NullString `json:"name"`
}

func (q *Queries) FindUsers(ctx context.Context) ([]FindUsersRow, error) {
	rows, err := q.db.Query(ctx, findUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FindUsersRow
	for rows.Next() {
		var i FindUsersRow
		if err := rows.Scan(
			&i.Uuid,
			&i.CreatedAt,
			&i.LastModifiedAt,
			&i.DeletedAt,
			&i.CreatedBy,
			&i.Email,
			&i.Name,
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

const registerUser = `-- name: RegisterUser :one
INSERT INTO users (email, name, password, created_at)
VALUES ($1, $2, $3, NOW())
RETURNING uuid, created_at, last_modified_at, deleted_at, created_by, email, name, password, verified_at
`

type RegisterUserParams struct {
	Email    string         `json:"email"`
	Name     sql.NullString `json:"name"`
	Password []byte         `json:"password"`
}

func (q *Queries) RegisterUser(ctx context.Context, arg RegisterUserParams) (User, error) {
	row := q.db.QueryRow(ctx, registerUser, arg.Email, arg.Name, arg.Password)
	var i User
	err := row.Scan(
		&i.Uuid,
		&i.CreatedAt,
		&i.LastModifiedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Email,
		&i.Name,
		&i.Password,
		&i.VerifiedAt,
	)
	return i, err
}
