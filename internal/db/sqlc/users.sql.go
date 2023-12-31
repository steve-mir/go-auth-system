// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: users.sql

package sqlc

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (
    id, name, email, username, password_hash, created_at,
    updated_at, is_suspended, is_deleted,
    login_attempts, lockout_duration, lockout_until,
    password_changed_at, is_verified
    )
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING id, name, email, username, password_hash, created_at, updated_at, is_suspended, is_verified, is_email_verified, is_deleted, login_attempts, lockout_duration, lockout_until, password_changed_at, deleted_at, suspended_at, email_verified_at
`

type CreateUserParams struct {
	ID                uuid.UUID      `json:"id"`
	Name              sql.NullString `json:"name"`
	Email             string         `json:"email"`
	Username          sql.NullString `json:"username"`
	PasswordHash      string         `json:"password_hash"`
	CreatedAt         sql.NullTime   `json:"created_at"`
	UpdatedAt         sql.NullTime   `json:"updated_at"`
	IsSuspended       bool           `json:"is_suspended"`
	IsDeleted         bool           `json:"is_deleted"`
	LoginAttempts     sql.NullInt32  `json:"login_attempts"`
	LockoutDuration   sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil      sql.NullTime   `json:"lockout_until"`
	PasswordChangedAt sql.NullTime   `json:"password_changed_at"`
	IsVerified        sql.NullBool   `json:"is_verified"`
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
		arg.IsSuspended,
		arg.IsDeleted,
		arg.LoginAttempts,
		arg.LockoutDuration,
		arg.LockoutUntil,
		arg.PasswordChangedAt,
		arg.IsVerified,
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
		&i.IsSuspended,
		&i.IsVerified,
		&i.IsEmailVerified,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
		&i.PasswordChangedAt,
		&i.DeletedAt,
		&i.SuspendedAt,
		&i.EmailVerifiedAt,
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

const getUserAndRoleByID = `-- name: GetUserAndRoleByID :one
SELECT users.id, users.name, users.email, users.username, users.password_hash, users.created_at, users.updated_at, users.is_suspended, users.is_verified, users.is_email_verified, users.is_deleted, users.login_attempts, users.lockout_duration, users.lockout_until, users.password_changed_at, users.deleted_at, users.suspended_at, users.email_verified_at, user_roles.role_id
FROM users
JOIN user_roles ON users.id = user_roles.user_id
WHERE users.id = $1
`

type GetUserAndRoleByIDRow struct {
	ID                uuid.UUID      `json:"id"`
	Name              sql.NullString `json:"name"`
	Email             string         `json:"email"`
	Username          sql.NullString `json:"username"`
	PasswordHash      string         `json:"password_hash"`
	CreatedAt         sql.NullTime   `json:"created_at"`
	UpdatedAt         sql.NullTime   `json:"updated_at"`
	IsSuspended       bool           `json:"is_suspended"`
	IsVerified        sql.NullBool   `json:"is_verified"`
	IsEmailVerified   sql.NullBool   `json:"is_email_verified"`
	IsDeleted         bool           `json:"is_deleted"`
	LoginAttempts     sql.NullInt32  `json:"login_attempts"`
	LockoutDuration   sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil      sql.NullTime   `json:"lockout_until"`
	PasswordChangedAt sql.NullTime   `json:"password_changed_at"`
	DeletedAt         sql.NullTime   `json:"deleted_at"`
	SuspendedAt       sql.NullTime   `json:"suspended_at"`
	EmailVerifiedAt   sql.NullTime   `json:"email_verified_at"`
	RoleID            int32          `json:"role_id"`
}

func (q *Queries) GetUserAndRoleByID(ctx context.Context, id uuid.UUID) (GetUserAndRoleByIDRow, error) {
	row := q.db.QueryRowContext(ctx, getUserAndRoleByID, id)
	var i GetUserAndRoleByIDRow
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Username,
		&i.PasswordHash,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.IsSuspended,
		&i.IsVerified,
		&i.IsEmailVerified,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
		&i.PasswordChangedAt,
		&i.DeletedAt,
		&i.SuspendedAt,
		&i.EmailVerifiedAt,
		&i.RoleID,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, name, email, username, password_hash, created_at, updated_at, is_suspended, is_verified, is_email_verified, is_deleted, login_attempts, lockout_duration, lockout_until, password_changed_at, deleted_at, suspended_at, email_verified_at FROM users WHERE email = $1 LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
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
		&i.IsSuspended,
		&i.IsVerified,
		&i.IsEmailVerified,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
		&i.PasswordChangedAt,
		&i.DeletedAt,
		&i.SuspendedAt,
		&i.EmailVerifiedAt,
	)
	return i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT id, name, email, username, password_hash, created_at, updated_at, is_suspended, is_verified, is_email_verified, is_deleted, login_attempts, lockout_duration, lockout_until, password_changed_at, deleted_at, suspended_at, email_verified_at FROM users WHERE id = $1 LIMIT 1
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
		&i.IsSuspended,
		&i.IsVerified,
		&i.IsEmailVerified,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
		&i.PasswordChangedAt,
		&i.DeletedAt,
		&i.SuspendedAt,
		&i.EmailVerifiedAt,
	)
	return i, err
}

const getUserByUsername = `-- name: GetUserByUsername :one
SELECT id, name, email, username, password_hash, created_at, updated_at, is_suspended, is_verified, is_email_verified, is_deleted, login_attempts, lockout_duration, lockout_until, password_changed_at, deleted_at, suspended_at, email_verified_at FROM users WHERE username = $1 LIMIT 1
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
		&i.IsSuspended,
		&i.IsVerified,
		&i.IsEmailVerified,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
		&i.PasswordChangedAt,
		&i.DeletedAt,
		&i.SuspendedAt,
		&i.EmailVerifiedAt,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET
    name = COALESCE($1, name),
    username = COALESCE($2,username),
    email = COALESCE($3,email),
    password_hash = COALESCE($4,password_hash),
    updated_at = COALESCE($5,updated_at),
    is_suspended = COALESCE($6,is_suspended),
    is_deleted = COALESCE($7,is_deleted),
    login_attempts = COALESCE($8,login_attempts),
    lockout_duration = COALESCE($9,lockout_duration),
    lockout_until = COALESCE($10,lockout_until),
    password_changed_at = COALESCE($11,password_changed_at),
    is_verified = COALESCE($12,is_verified)
WHERE
    id = $13
RETURNING id, name, email, username, password_hash, created_at, updated_at, is_suspended, is_verified, is_email_verified, is_deleted, login_attempts, lockout_duration, lockout_until, password_changed_at, deleted_at, suspended_at, email_verified_at
`

type UpdateUserParams struct {
	Name              sql.NullString `json:"name"`
	Username          sql.NullString `json:"username"`
	Email             sql.NullString `json:"email"`
	PasswordHash      sql.NullString `json:"password_hash"`
	UpdatedAt         sql.NullTime   `json:"updated_at"`
	IsSuspended       sql.NullBool   `json:"is_suspended"`
	IsDeleted         sql.NullBool   `json:"is_deleted"`
	LoginAttempts     sql.NullInt32  `json:"login_attempts"`
	LockoutDuration   sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil      sql.NullTime   `json:"lockout_until"`
	PasswordChangedAt sql.NullTime   `json:"password_changed_at"`
	IsVerified        sql.NullBool   `json:"is_verified"`
	ID                uuid.UUID      `json:"id"`
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser,
		arg.Name,
		arg.Username,
		arg.Email,
		arg.PasswordHash,
		arg.UpdatedAt,
		arg.IsSuspended,
		arg.IsDeleted,
		arg.LoginAttempts,
		arg.LockoutDuration,
		arg.LockoutUntil,
		arg.PasswordChangedAt,
		arg.IsVerified,
		arg.ID,
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
		&i.IsSuspended,
		&i.IsVerified,
		&i.IsEmailVerified,
		&i.IsDeleted,
		&i.LoginAttempts,
		&i.LockoutDuration,
		&i.LockoutUntil,
		&i.PasswordChangedAt,
		&i.DeletedAt,
		&i.SuspendedAt,
		&i.EmailVerifiedAt,
	)
	return i, err
}

const updateUserEmailVerified = `-- name: UpdateUserEmailVerified :exec
UPDATE users
SET is_email_verified = $3,
email_verified_at = $2
WHERE id = $1
`

type UpdateUserEmailVerifiedParams struct {
	ID              uuid.UUID    `json:"id"`
	EmailVerifiedAt sql.NullTime `json:"email_verified_at"`
	IsEmailVerified sql.NullBool `json:"is_email_verified"`
}

func (q *Queries) UpdateUserEmailVerified(ctx context.Context, arg UpdateUserEmailVerifiedParams) error {
	_, err := q.db.ExecContext(ctx, updateUserEmailVerified, arg.ID, arg.EmailVerifiedAt, arg.IsEmailVerified)
	return err
}

const updateUserOld = `-- name: UpdateUserOld :exec
UPDATE users
SET name = $2, email = $3, username = $4, password_hash = $5, updated_at = $6, is_suspended = $7, is_deleted = $8, login_attempts = $9, lockout_duration = $10, lockout_until = $11
WHERE id = $1
`

type UpdateUserOldParams struct {
	ID              uuid.UUID      `json:"id"`
	Name            sql.NullString `json:"name"`
	Email           string         `json:"email"`
	Username        sql.NullString `json:"username"`
	PasswordHash    string         `json:"password_hash"`
	UpdatedAt       sql.NullTime   `json:"updated_at"`
	IsSuspended     bool           `json:"is_suspended"`
	IsDeleted       bool           `json:"is_deleted"`
	LoginAttempts   sql.NullInt32  `json:"login_attempts"`
	LockoutDuration sql.NullInt32  `json:"lockout_duration"`
	LockoutUntil    sql.NullTime   `json:"lockout_until"`
}

func (q *Queries) UpdateUserOld(ctx context.Context, arg UpdateUserOldParams) error {
	_, err := q.db.ExecContext(ctx, updateUserOld,
		arg.ID,
		arg.Name,
		arg.Email,
		arg.Username,
		arg.PasswordHash,
		arg.UpdatedAt,
		arg.IsSuspended,
		arg.IsDeleted,
		arg.LoginAttempts,
		arg.LockoutDuration,
		arg.LockoutUntil,
	)
	return err
}

const updateUserPassword = `-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2
WHERE email = $1
`

type UpdateUserPasswordParams struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

func (q *Queries) UpdateUserPassword(ctx context.Context, arg UpdateUserPasswordParams) error {
	_, err := q.db.ExecContext(ctx, updateUserPassword, arg.Email, arg.PasswordHash)
	return err
}

const updateUserSuspension = `-- name: UpdateUserSuspension :exec
UPDATE users
SET is_suspended = $3, suspended_at = $2
WHERE id = $1
`

type UpdateUserSuspensionParams struct {
	ID          uuid.UUID    `json:"id"`
	SuspendedAt sql.NullTime `json:"suspended_at"`
	IsSuspended bool         `json:"is_suspended"`
}

func (q *Queries) UpdateUserSuspension(ctx context.Context, arg UpdateUserSuspensionParams) error {
	_, err := q.db.ExecContext(ctx, updateUserSuspension, arg.ID, arg.SuspendedAt, arg.IsSuspended)
	return err
}
