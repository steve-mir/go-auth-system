-- Create a new banned user
-- name: CreateBannedUser :one
INSERT INTO banned_users (user_id, banned_at, reason)
VALUES ($1, $2, $3) RETURNING *;

-- Get all banned users with a limit
-- name: GetAllBannedUsers :many
SELECT * FROM banned_users
LIMIT $1;

-- Get banned users by user ID
-- name: GetBannedUsersByUserID :many
SELECT * FROM banned_users
WHERE user_id = $1;

-- Update a banned user
-- name: UpdateBannedUser :one
UPDATE banned_users
SET banned_at = $1, reason = $2
WHERE id = $3 RETURNING *;

-- Delete a banned user
-- name: DeleteBannedUser :exec
DELETE FROM banned_users
WHERE id = $1;