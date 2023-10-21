// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0
// source: users.sql

package sqlc

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until
`

type CreateUserParams struct {
	ID              uuid.UUID      `json:"id"`
	Name            sql.NullString `json:"name"`
	Email           sql.NullString `json:"email"`
	Username        sql.NullString `json:"username"`
	PasswordHash    sql.NullString `json:"password_hash"`
	CreatedAt       interface{}    `json:"created_at"`
	UpdatedAt       sql.NullTime   `json:"updated_at"`
	LastLogin       sql.NullTime   `json:"last_login"`
	IsSuspended     sql.NullBool   `json:"is_suspended"`
	IsDeleted       sql.NullBool   `json:"is_deleted"`
	LoginAttempts   sql.NullInt32  `json:"login_attempts"`
	LockoutDuration sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil    sql.NullTime   `json:"lockout_until"`
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser,
		arg.ID,
		arg.Name,
		arg.Email,
		arg.Username,
		arg.PasswordHash,
		arg.CreatedAt,
		arg.UpdatedAt,
		arg.LastLogin,
		arg.IsSuspended,
		arg.IsDeleted,
		arg.LoginAttempts,
		arg.LockoutDuration,
		arg.LockoutUntil,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Username,
		&i.PasswordHash,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.LastLogin,
		&i.IsSuspended,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
	)
	return i, err
}

const deleteUserByID = `-- name: DeleteUserByID :exec
DELETE FROM users WHERE id = $1
`

func (q *Queries) DeleteUserByID(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteUserByID, id)
	return err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until FROM users WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email sql.NullString) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Username,
		&i.PasswordHash,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.LastLogin,
		&i.IsSuspended,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
	)
	return i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until FROM users WHERE id = $1
`

func (q *Queries) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Username,
		&i.PasswordHash,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.LastLogin,
		&i.IsSuspended,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
	)
	return i, err
}

const getUserByUsername = `-- name: GetUserByUsername :one
SELECT id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until FROM users WHERE username = $1
`

func (q *Queries) GetUserByUsername(ctx context.Context, username sql.NullString) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByUsername, username)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Username,
		&i.PasswordHash,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.LastLogin,
		&i.IsSuspended,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET name = $2, email = $3, username = $4, password_hash = $5, updated_at = $6, last_login = $7, is_suspended = $8, is_deleted = $9, login_attempts = $10, lockout_duration = $11, lockout_until = $12
WHERE id = $1
RETURNING id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until
`

type UpdateUserParams struct {
	ID              uuid.UUID      `json:"id"`
	Name            sql.NullString `json:"name"`
	Email           sql.NullString `json:"email"`
	Username        sql.NullString `json:"username"`
	PasswordHash    sql.NullString `json:"password_hash"`
	UpdatedAt       sql.NullTime   `json:"updated_at"`
	LastLogin       sql.NullTime   `json:"last_login"`
	IsSuspended     sql.NullBool   `json:"is_suspended"`
	IsDeleted       sql.NullBool   `json:"is_deleted"`
	LoginAttempts   sql.NullInt32  `json:"login_attempts"`
	LockoutDuration sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil    sql.NullTime   `json:"lockout_until"`
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser,
		arg.ID,
		arg.Name,
		arg.Email,
		arg.Username,
		arg.PasswordHash,
		arg.UpdatedAt,
		arg.LastLogin,
		arg.IsSuspended,
		arg.IsDeleted,
		arg.LoginAttempts,
		arg.LockoutDuration,
		arg.LockoutUntil,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Username,
		&i.PasswordHash,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.LastLogin,
		&i.IsSuspended,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
	)
	return i, err
}
