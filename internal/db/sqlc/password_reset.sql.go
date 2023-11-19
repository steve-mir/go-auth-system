// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0
// source: password_reset.sql

package sqlc

import (
	"context"
	"database/sql"
	"time"
)

const createPasswordResetRequest = `-- name: CreatePasswordResetRequest :exec
INSERT INTO password_reset_requests (email, token, used, expires_at)
VALUES ($1, $2, $3, $4)
`

type CreatePasswordResetRequestParams struct {
	Email     string       `json:"email"`
	Token     string       `json:"token"`
	Used      sql.NullBool `json:"used"`
	ExpiresAt time.Time    `json:"expires_at"`
}

func (q *Queries) CreatePasswordResetRequest(ctx context.Context, arg CreatePasswordResetRequestParams) error {
	_, err := q.db.ExecContext(ctx, createPasswordResetRequest,
		arg.Email,
		arg.Token,
		arg.Used,
		arg.ExpiresAt,
	)
	return err
}

const deletePasswordResetRequestByID = `-- name: DeletePasswordResetRequestByID :exec
DELETE FROM password_reset_requests WHERE id = $1
`

func (q *Queries) DeletePasswordResetRequestByID(ctx context.Context, id int32) error {
	_, err := q.db.ExecContext(ctx, deletePasswordResetRequestByID, id)
	return err
}

const getPasswordResetRequestByID = `-- name: GetPasswordResetRequestByID :one
SELECT id, email, token, used, created_at, expires_at FROM password_reset_requests WHERE id = $1 LIMIT 1
`

func (q *Queries) GetPasswordResetRequestByID(ctx context.Context, id int32) (PasswordResetRequest, error) {
	row := q.db.QueryRowContext(ctx, getPasswordResetRequestByID, id)
	var i PasswordResetRequest
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Token,
		&i.Used,
		&i.CreatedAt,
		&i.ExpiresAt,
	)
	return i, err
}

const getPasswordResetRequestByToken = `-- name: GetPasswordResetRequestByToken :one
SELECT id, email, token, used, created_at, expires_at FROM password_reset_requests WHERE token = $1 LIMIT 1
`

func (q *Queries) GetPasswordResetRequestByToken(ctx context.Context, token string) (PasswordResetRequest, error) {
	row := q.db.QueryRowContext(ctx, getPasswordResetRequestByToken, token)
	var i PasswordResetRequest
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Token,
		&i.Used,
		&i.CreatedAt,
		&i.ExpiresAt,
	)
	return i, err
}

const updatePasswordResetRequest = `-- name: UpdatePasswordResetRequest :exec
UPDATE password_reset_requests SET used = $1 WHERE id = $2
`

type UpdatePasswordResetRequestParams struct {
	Used sql.NullBool `json:"used"`
	ID   int32        `json:"id"`
}

func (q *Queries) UpdatePasswordResetRequest(ctx context.Context, arg UpdatePasswordResetRequestParams) error {
	_, err := q.db.ExecContext(ctx, updatePasswordResetRequest, arg.Used, arg.ID)
	return err
}

const updatePasswordResetRequestByToken = `-- name: UpdatePasswordResetRequestByToken :exec
UPDATE password_reset_requests SET used = $1 WHERE token = $2
`

type UpdatePasswordResetRequestByTokenParams struct {
	Used  sql.NullBool `json:"used"`
	Token string       `json:"token"`
}

func (q *Queries) UpdatePasswordResetRequestByToken(ctx context.Context, arg UpdatePasswordResetRequestByTokenParams) error {
	_, err := q.db.ExecContext(ctx, updatePasswordResetRequestByToken, arg.Used, arg.Token)
	return err
}