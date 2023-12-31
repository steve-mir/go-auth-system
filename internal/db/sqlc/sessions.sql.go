// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: sessions.sql

package sqlc

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

const createSession = `-- name: CreateSession :one
INSERT INTO sessions (id, user_id, email, refresh_token, user_agent,
ip_address, is_blocked, expires_at, created_at, last_active_at, is_breached)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id, user_id, email, refresh_token, user_agent, ip_address, is_blocked, is_breached, expires_at, created_at, last_active_at
`

type CreateSessionParams struct {
	ID           uuid.UUID      `json:"id"`
	UserID       uuid.UUID      `json:"user_id"`
	Email        sql.NullString `json:"email"`
	RefreshToken string         `json:"refresh_token"`
	UserAgent    string         `json:"user_agent"`
	IpAddress    pqtype.Inet    `json:"ip_address"`
	IsBlocked    bool           `json:"is_blocked"`
	ExpiresAt    time.Time      `json:"expires_at"`
	CreatedAt    sql.NullTime   `json:"created_at"`
	LastActiveAt sql.NullTime   `json:"last_active_at"`
	IsBreached   bool           `json:"is_breached"`
}

// Create a new session
func (q *Queries) CreateSession(ctx context.Context, arg CreateSessionParams) (Session, error) {
	row := q.db.QueryRowContext(ctx, createSession,
		arg.ID,
		arg.UserID,
		arg.Email,
		arg.RefreshToken,
		arg.UserAgent,
		arg.IpAddress,
		arg.IsBlocked,
		arg.ExpiresAt,
		arg.CreatedAt,
		arg.LastActiveAt,
		arg.IsBreached,
	)
	var i Session
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Email,
		&i.RefreshToken,
		&i.UserAgent,
		&i.IpAddress,
		&i.IsBlocked,
		&i.IsBreached,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.LastActiveAt,
	)
	return i, err
}

const deleteSession = `-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1
`

// Delete a session
func (q *Queries) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteSession, id)
	return err
}

const getAllSessions = `-- name: GetAllSessions :many
SELECT id, user_id, email, refresh_token, user_agent, ip_address, is_blocked, is_breached, expires_at, created_at, last_active_at FROM sessions
LIMIT $1
`

// Get all sessions with a limit
func (q *Queries) GetAllSessions(ctx context.Context, limit int32) ([]Session, error) {
	rows, err := q.db.QueryContext(ctx, getAllSessions, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Session{}
	for rows.Next() {
		var i Session
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.Email,
			&i.RefreshToken,
			&i.UserAgent,
			&i.IpAddress,
			&i.IsBlocked,
			&i.IsBreached,
			&i.ExpiresAt,
			&i.CreatedAt,
			&i.LastActiveAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getSessionsByID = `-- name: GetSessionsByID :one
SELECT id, user_id, email, refresh_token, user_agent, ip_address, is_blocked, is_breached, expires_at, created_at, last_active_at FROM sessions WHERE id = $1 LIMIT 1
`

func (q *Queries) GetSessionsByID(ctx context.Context, id uuid.UUID) (Session, error) {
	row := q.db.QueryRowContext(ctx, getSessionsByID, id)
	var i Session
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Email,
		&i.RefreshToken,
		&i.UserAgent,
		&i.IpAddress,
		&i.IsBlocked,
		&i.IsBreached,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.LastActiveAt,
	)
	return i, err
}

const getSessionsByToken = `-- name: GetSessionsByToken :one
SELECT id, user_id, email, refresh_token, user_agent, ip_address, is_blocked, is_breached, expires_at, created_at, last_active_at FROM sessions WHERE refresh_token = $1 LIMIT 1
`

func (q *Queries) GetSessionsByToken(ctx context.Context, refreshToken string) (Session, error) {
	row := q.db.QueryRowContext(ctx, getSessionsByToken, refreshToken)
	var i Session
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Email,
		&i.RefreshToken,
		&i.UserAgent,
		&i.IpAddress,
		&i.IsBlocked,
		&i.IsBreached,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.LastActiveAt,
	)
	return i, err
}

const getSessionsByUserID = `-- name: GetSessionsByUserID :many
SELECT id, user_id, email, refresh_token, user_agent, ip_address, is_blocked, is_breached, expires_at, created_at, last_active_at FROM sessions
WHERE user_id = $1
`

func (q *Queries) GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := q.db.QueryContext(ctx, getSessionsByUserID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Session{}
	for rows.Next() {
		var i Session
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.Email,
			&i.RefreshToken,
			&i.UserAgent,
			&i.IpAddress,
			&i.IsBlocked,
			&i.IsBreached,
			&i.ExpiresAt,
			&i.CreatedAt,
			&i.LastActiveAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateIsBlockedByUserId = `-- name: UpdateIsBlockedByUserId :exec
UPDATE sessions SET is_blocked = $2 WHERE user_id = $1
`

type UpdateIsBlockedByUserIdParams struct {
	UserID    uuid.UUID `json:"user_id"`
	IsBlocked bool      `json:"is_blocked"`
}

func (q *Queries) UpdateIsBlockedByUserId(ctx context.Context, arg UpdateIsBlockedByUserIdParams) error {
	_, err := q.db.ExecContext(ctx, updateIsBlockedByUserId, arg.UserID, arg.IsBlocked)
	return err
}

const updateNewSession = `-- name: UpdateNewSession :exec
UPDATE sessions 
  SET refresh_token = $2, user_agent = $3, ip_address = $4, expires_at = $5, created_at = $6, last_active_at = $7
WHERE id = $1
`

type UpdateNewSessionParams struct {
	ID           uuid.UUID    `json:"id"`
	RefreshToken string       `json:"refresh_token"`
	UserAgent    string       `json:"user_agent"`
	IpAddress    pqtype.Inet  `json:"ip_address"`
	ExpiresAt    time.Time    `json:"expires_at"`
	CreatedAt    sql.NullTime `json:"created_at"`
	LastActiveAt sql.NullTime `json:"last_active_at"`
}

func (q *Queries) UpdateNewSession(ctx context.Context, arg UpdateNewSessionParams) error {
	_, err := q.db.ExecContext(ctx, updateNewSession,
		arg.ID,
		arg.RefreshToken,
		arg.UserAgent,
		arg.IpAddress,
		arg.ExpiresAt,
		arg.CreatedAt,
		arg.LastActiveAt,
	)
	return err
}

const updateSession = `-- name: UpdateSession :exec
UPDATE sessions
  set is_breached = $2
WHERE id = $1
`

type UpdateSessionParams struct {
	ID         uuid.UUID `json:"id"`
	IsBreached bool      `json:"is_breached"`
}

// Update a session
func (q *Queries) UpdateSession(ctx context.Context, arg UpdateSessionParams) error {
	_, err := q.db.ExecContext(ctx, updateSession, arg.ID, arg.IsBreached)
	return err
}

const updateSessionToken = `-- name: UpdateSessionToken :exec
UPDATE sessions SET is_blocked = $2 WHERE id = $1
`

type UpdateSessionTokenParams struct {
	ID        uuid.UUID `json:"id"`
	IsBlocked bool      `json:"is_blocked"`
}

func (q *Queries) UpdateSessionToken(ctx context.Context, arg UpdateSessionTokenParams) error {
	_, err := q.db.ExecContext(ctx, updateSessionToken, arg.ID, arg.IsBlocked)
	return err
}
