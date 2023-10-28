// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0
// source: user_auth.sql

package sqlc

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const regUserRole = `-- name: RegUserRole :one
SELECT users.id, users.name, users.email, users.username, users.password_hash, users.created_at, users.updated_at, users.is_suspended, users.is_verified, users.is_email_verified, users.is_deleted, users.login_attempts, users.lockout_duration, users.lockout_until, users.password_changed_at, users.deleted_at, users.suspended_at, users.email_verified_at, user_roles.role_id
FROM users
JOIN user_roles ON users.id = user_roles.user_id
WHERE users.id = $1
`

type RegUserRoleRow struct {
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
	RoleID            sql.NullInt32  `json:"role_id"`
}

func (q *Queries) RegUserRole(ctx context.Context, id uuid.UUID) (RegUserRoleRow, error) {
	row := q.db.QueryRowContext(ctx, regUserRole, id)
	var i RegUserRoleRow
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
