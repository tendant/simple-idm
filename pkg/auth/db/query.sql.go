// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const findUserByUserUuid = `-- name: FindUserByUserUuid :one
SELECT users.uuid, name, username, email, password
FROM users
WHERE uuid = $1
`

type FindUserByUserUuidRow struct {
	Uuid     uuid.UUID      `json:"uuid"`
	Name     sql.NullString `json:"name"`
	Username sql.NullString `json:"username"`
	Email    string         `json:"email"`
	Password sql.NullString `json:"password"`
}

func (q *Queries) FindUserByUserUuid(ctx context.Context, argUuid uuid.UUID) (FindUserByUserUuidRow, error) {
	row := q.db.QueryRow(ctx, findUserByUserUuid, argUuid)
	var i FindUserByUserUuidRow
	err := row.Scan(
		&i.Uuid,
		&i.Name,
		&i.Username,
		&i.Email,
		&i.Password,
	)
	return i, err
}