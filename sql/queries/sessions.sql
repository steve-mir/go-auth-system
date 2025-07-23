-- name: CreateSession :one
INSERT INTO user_sessions (
    user_id, token_hash, token_type, expires_at, ip_address, user_agent
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetSessionByTokenHash :one
SELECT * FROM user_sessions WHERE token_hash = $1;

-- -- name: GetSessionByID :one
-- SELECT * FROM user_sessions WHERE id = $1;

-- -- name: GetUserSessions :many
-- SELECT * FROM user_sessions 
-- WHERE user_id = $1 AND expires_at > NOW()
-- ORDER BY created_at DESC
-- LIMIT $2 OFFSET $3;

-- name: UpdateSessionLastUsed :exec
UPDATE user_sessions SET
    last_used_at = NOW()
WHERE id = $1;

-- -- name: DeleteSession :exec
-- DELETE FROM user_sessions WHERE id = $1;

-- name: DeleteSessionByTokenHash :exec
DELETE FROM user_sessions WHERE token_hash = $1;

-- -- name: DeleteUserSessions :exec
-- DELETE FROM user_sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM user_sessions WHERE expires_at < NOW();

-- name: CountUserSessions :one
SELECT COUNT(*) FROM user_sessions 
WHERE user_id = $1 AND expires_at > NOW();

-- name: GetSessionsForCleanup :many
SELECT id, token_hash FROM user_sessions 
WHERE expires_at < NOW()
LIMIT $1;