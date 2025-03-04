// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: query.sql

package iamdb

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const createRole = `-- name: CreateRole :one
INSERT INTO roles (name) VALUES ($1) RETURNING id
`

func (q *Queries) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	row := q.db.QueryRow(ctx, createRole, name)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const createUser = `-- name: CreateUser :one
INSERT INTO users (email, name, login_id)
VALUES ($1, $2, $3)
RETURNING id, created_at, last_modified_at, deleted_at, created_by, email, name, login_id
`

type CreateUserParams struct {
	Email   string         `json:"email"`
	Name    sql.NullString `json:"name"`
	LoginID uuid.NullUUID  `json:"login_id"`
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRow(ctx, createUser, arg.Email, arg.Name, arg.LoginID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.LastModifiedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Email,
		&i.Name,
		&i.LoginID,
	)
	return i, err
}

const createUserRole = `-- name: CreateUserRole :one
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
RETURNING user_id, role_id
`

type CreateUserRoleParams struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

func (q *Queries) CreateUserRole(ctx context.Context, arg CreateUserRoleParams) (UserRole, error) {
	row := q.db.QueryRow(ctx, createUserRole, arg.UserID, arg.RoleID)
	var i UserRole
	err := row.Scan(&i.UserID, &i.RoleID)
	return i, err
}

type CreateUserRoleBatchParams struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

const deleteRole = `-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1
`

func (q *Queries) DeleteRole(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, deleteRole, id)
	return err
}

const deleteUser = `-- name: DeleteUser :exec
UPDATE users
SET deleted_at = CURRENT_TIMESTAMP
WHERE id = $1
`

func (q *Queries) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, deleteUser, id)
	return err
}

const deleteUserRoles = `-- name: DeleteUserRoles :exec
DELETE FROM user_roles
WHERE user_id = $1
`

func (q *Queries) DeleteUserRoles(ctx context.Context, userID uuid.UUID) error {
	_, err := q.db.Exec(ctx, deleteUserRoles, userID)
	return err
}

const findRoles = `-- name: FindRoles :many

SELECT id, name
FROM roles
ORDER BY name ASC
`

type FindRolesRow struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// Role queries
func (q *Queries) FindRoles(ctx context.Context) ([]FindRolesRow, error) {
	rows, err := q.db.Query(ctx, findRoles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FindRolesRow
	for rows.Next() {
		var i FindRolesRow
		if err := rows.Scan(&i.ID, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const findUsers = `-- name: FindUsers :many
SELECT u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name, u.login_id, l.username
FROM users u
JOIN login l ON u.login_id = l.id
WHERE u.deleted_at IS NULL
ORDER BY u.created_at ASC
limit 20
`

type FindUsersRow struct {
	ID             uuid.UUID      `json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	LastModifiedAt time.Time      `json:"last_modified_at"`
	DeletedAt      sql.NullTime   `json:"deleted_at"`
	CreatedBy      sql.NullString `json:"created_by"`
	Email          string         `json:"email"`
	Name           sql.NullString `json:"name"`
	LoginID        uuid.NullUUID  `json:"login_id"`
	Username       sql.NullString `json:"username"`
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
			&i.ID,
			&i.CreatedAt,
			&i.LastModifiedAt,
			&i.DeletedAt,
			&i.CreatedBy,
			&i.Email,
			&i.Name,
			&i.LoginID,
			&i.Username,
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

const findUsersWithRoles = `-- name: FindUsersWithRoles :many
SELECT u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name,
       json_agg(json_build_object(
           'id', r.id,
           'name', r.name
       )) as roles,
       l.username,
       u.login_id
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
LEFT JOIN login l ON u.login_id = l.id
WHERE u.deleted_at IS NULL
GROUP BY u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name, l.username, u.login_id
ORDER BY u.created_at ASC
LIMIT 20
`

type FindUsersWithRolesRow struct {
	ID             uuid.UUID      `json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	LastModifiedAt time.Time      `json:"last_modified_at"`
	DeletedAt      sql.NullTime   `json:"deleted_at"`
	CreatedBy      sql.NullString `json:"created_by"`
	Email          string         `json:"email"`
	Name           sql.NullString `json:"name"`
	Roles          []byte         `json:"roles"`
	Username       sql.NullString `json:"username"`
	LoginID        uuid.NullUUID  `json:"login_id"`
}

func (q *Queries) FindUsersWithRoles(ctx context.Context) ([]FindUsersWithRolesRow, error) {
	rows, err := q.db.Query(ctx, findUsersWithRoles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FindUsersWithRolesRow
	for rows.Next() {
		var i FindUsersWithRolesRow
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.LastModifiedAt,
			&i.DeletedAt,
			&i.CreatedBy,
			&i.Email,
			&i.Name,
			&i.Roles,
			&i.Username,
			&i.LoginID,
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

const getRoleById = `-- name: GetRoleById :one
SELECT id, name
FROM roles
WHERE id = $1
`

type GetRoleByIdRow struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

func (q *Queries) GetRoleById(ctx context.Context, id uuid.UUID) (GetRoleByIdRow, error) {
	row := q.db.QueryRow(ctx, getRoleById, id)
	var i GetRoleByIdRow
	err := row.Scan(&i.ID, &i.Name)
	return i, err
}

const getRoleUsers = `-- name: GetRoleUsers :many
SELECT u.id, u.email, u.name
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
WHERE ur.role_id = $1
ORDER BY u.email
`

type GetRoleUsersRow struct {
	ID    uuid.UUID      `json:"id"`
	Email string         `json:"email"`
	Name  sql.NullString `json:"name"`
}

func (q *Queries) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]GetRoleUsersRow, error) {
	rows, err := q.db.Query(ctx, getRoleUsers, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetRoleUsersRow
	for rows.Next() {
		var i GetRoleUsersRow
		if err := rows.Scan(&i.ID, &i.Email, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUserById = `-- name: GetUserById :one
SELECT id, created_at, last_modified_at, deleted_at, created_by, email, name
FROM users
WHERE id = $1
`

type GetUserByIdRow struct {
	ID             uuid.UUID      `json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	LastModifiedAt time.Time      `json:"last_modified_at"`
	DeletedAt      sql.NullTime   `json:"deleted_at"`
	CreatedBy      sql.NullString `json:"created_by"`
	Email          string         `json:"email"`
	Name           sql.NullString `json:"name"`
}

func (q *Queries) GetUserById(ctx context.Context, id uuid.UUID) (GetUserByIdRow, error) {
	row := q.db.QueryRow(ctx, getUserById, id)
	var i GetUserByIdRow
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.LastModifiedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Email,
		&i.Name,
	)
	return i, err
}

const getUserWithRoles = `-- name: GetUserWithRoles :one
SELECT u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name,
       json_agg(json_build_object(
           'id', r.id,
           'name', r.name
       )) as roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1
GROUP BY u.id, u.created_at, u.last_modified_at, u.deleted_at, u.created_by, u.email, u.name
`

type GetUserWithRolesRow struct {
	ID             uuid.UUID      `json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	LastModifiedAt time.Time      `json:"last_modified_at"`
	DeletedAt      sql.NullTime   `json:"deleted_at"`
	CreatedBy      sql.NullString `json:"created_by"`
	Email          string         `json:"email"`
	Name           sql.NullString `json:"name"`
	Roles          []byte         `json:"roles"`
}

func (q *Queries) GetUserWithRoles(ctx context.Context, id uuid.UUID) (GetUserWithRolesRow, error) {
	row := q.db.QueryRow(ctx, getUserWithRoles, id)
	var i GetUserWithRolesRow
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.LastModifiedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Email,
		&i.Name,
		&i.Roles,
	)
	return i, err
}

const hasUsers = `-- name: HasUsers :one
SELECT EXISTS (
    SELECT 1 FROM user_roles WHERE role_id = $1
) as has_users
`

func (q *Queries) HasUsers(ctx context.Context, roleID uuid.UUID) (bool, error) {
	row := q.db.QueryRow(ctx, hasUsers, roleID)
	var has_users bool
	err := row.Scan(&has_users)
	return has_users, err
}

const removeUserFromRole = `-- name: RemoveUserFromRole :exec
DELETE FROM user_roles 
WHERE user_id = $1 AND role_id = $2
`

type RemoveUserFromRoleParams struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

func (q *Queries) RemoveUserFromRole(ctx context.Context, arg RemoveUserFromRoleParams) error {
	_, err := q.db.Exec(ctx, removeUserFromRole, arg.UserID, arg.RoleID)
	return err
}

const updateRole = `-- name: UpdateRole :exec
UPDATE roles SET name = $2 WHERE id = $1
`

type UpdateRoleParams struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

func (q *Queries) UpdateRole(ctx context.Context, arg UpdateRoleParams) error {
	_, err := q.db.Exec(ctx, updateRole, arg.ID, arg.Name)
	return err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users SET name = $2 WHERE id = $1
RETURNING id, created_at, last_modified_at, deleted_at, created_by, email, name, login_id
`

type UpdateUserParams struct {
	ID   uuid.UUID      `json:"id"`
	Name sql.NullString `json:"name"`
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRow(ctx, updateUser, arg.ID, arg.Name)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.LastModifiedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Email,
		&i.Name,
		&i.LoginID,
	)
	return i, err
}

const updateUserLoginID = `-- name: UpdateUserLoginID :one
UPDATE users SET login_id = $2 WHERE id = $1
RETURNING id, created_at, last_modified_at, deleted_at, created_by, email, name, login_id
`

type UpdateUserLoginIDParams struct {
	ID      uuid.UUID     `json:"id"`
	LoginID uuid.NullUUID `json:"login_id"`
}

func (q *Queries) UpdateUserLoginID(ctx context.Context, arg UpdateUserLoginIDParams) (User, error) {
	row := q.db.QueryRow(ctx, updateUserLoginID, arg.ID, arg.LoginID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.LastModifiedAt,
		&i.DeletedAt,
		&i.CreatedBy,
		&i.Email,
		&i.Name,
		&i.LoginID,
	)
	return i, err
}
