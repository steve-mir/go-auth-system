-- Create a new session
-- name: CreateSession :one
INSERT INTO sessions (id, user_id, email, refresh_token, user_agent, ip_address, is_blocked, expires_at, created_at, last_active_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *;

-- Get all sessions with a limit
-- name: GetAllSessions :many
SELECT * FROM sessions
LIMIT $1;

-- Get sessions by user ID
-- name: GetSessionsByUserID :many
SELECT * FROM sessions
WHERE user_id = $1;

-- Update a session
-- name: UpdateSession :one
UPDATE sessions
SET user_id = $1, email = $2, refresh_token = $3, user_agent = $4, ip_address = $5, is_blocked = $6, expires_at = $7, created_at = $8, last_active_at = $9
WHERE id = $10 RETURNING *;

-- Delete a session
-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;