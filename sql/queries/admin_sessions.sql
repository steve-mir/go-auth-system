-- name: GetAllSessions :many
SELECT 
    s.id, s.user_id, u.email, s.ip_address, s.user_agent,
    s.created_at, s.last_used_at, s.expires_at, s.token_type,
    CASE WHEN s.expires_at > NOW() THEN true ELSE false END as is_active
FROM user_sessions s
JOIN users u ON s.user_id = u.id
WHERE ($1::uuid IS NULL OR s.user_id = $1)
ORDER BY 
    CASE WHEN $2 = 'created_at' THEN s.created_at END,
    CASE WHEN $2 = 'last_used_at' THEN s.last_used_at END,
    CASE WHEN $2 = 'expires_at' THEN s.expires_at END,
    CASE WHEN $2 = 'user_email' THEN u.email END
LIMIT $3 OFFSET $4;

-- name: CountAllSessions :one
SELECT COUNT(*)
FROM user_sessions s
JOIN users u ON s.user_id = u.id
WHERE ($1::uuid IS NULL OR s.user_id = $1);

-- name: DeleteSession :exec
DELETE FROM user_sessions WHERE id = $1;

-- name: GetSessionByID :one
SELECT 
    s.id, s.user_id, u.email, s.ip_address, s.user_agent,
    s.created_at, s.last_used_at, s.expires_at, s.token_type,
    CASE WHEN s.expires_at > NOW() THEN true ELSE false END as is_active
FROM user_sessions s
JOIN users u ON s.user_id = u.id
WHERE s.id = $1;

-- name: GetUserSessions :many
SELECT 
    s.id, s.user_id, u.email, s.ip_address, s.user_agent,
    s.created_at, s.last_used_at, s.expires_at, s.token_type,
    CASE WHEN s.expires_at > NOW() THEN true ELSE false END as is_active
FROM user_sessions s
JOIN users u ON s.user_id = u.id
WHERE s.user_id = $1
ORDER BY s.created_at DESC
LIMIT $2 OFFSET $3;

-- name: DeleteUserSessions :exec
DELETE FROM user_sessions WHERE user_id = $1;

-- name: GetActiveSessionsCount :one
SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW();

-- name: CleanupExpiredSessions :exec
DELETE FROM user_sessions WHERE expires_at <= NOW();