-- Create a new session
-- name: CreateSession :one
INSERT INTO sessions (id, user_id, email, refresh_token, user_agent,
ip_address, is_blocked, expires_at, created_at, last_active_at, is_breached)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *;

-- Get all sessions with a limit
-- name: GetAllSessions :many
SELECT * FROM sessions
LIMIT $1;

-- name: GetSessionsByUserID :many
SELECT * FROM sessions
WHERE user_id = $1;

-- name: GetSessionsByID :one
SELECT * FROM sessions WHERE id = $1 LIMIT 1;

-- name: GetSessionsByToken :one
SELECT * FROM sessions WHERE refresh_token = $1 LIMIT 1;

-- Update a session
-- name: UpdateSession :exec
UPDATE sessions
  set is_breached = $2
WHERE id = $1;

-- name: UpdateIsBlockedByUserId :exec
UPDATE sessions SET is_blocked = $2 WHERE user_id = $1;

-- name: UpdateSessionToken :exec
UPDATE sessions SET is_blocked = $2 WHERE id = $1;

-- name: UpdateNewSession :exec
UPDATE sessions 
  SET refresh_token = $2, user_agent = $3, ip_address = $4, expires_at = $5, created_at = $6, last_active_at = $7
WHERE id = $1;


CREATE TABLE "sessions" (


  "refresh_token" varchar NOT NULL, -- Update on token rotation. When trying to update or rotate token if token doesn't exist. Block all session and user account
  "user_agent" text NOT NULL,
  "ip_address" inet NOT NULL,
  "is_blocked" boolean NOT NULL,
  "is_breached" boolean NOT NULL, -- Identifies whether a security breached occurred from here leading to blocking of other sessions and user.
  "expires_at" timestamptz NOT NULL, -- Update on token rotation, When session/refresh token will end. This will logged the user out.
  "created_at" timestamptz, -- When session token was created
  "last_active_at" timestamptz -- Update on token rotation. Used to identify when last the user logged in
);

-- Delete a session
-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;
