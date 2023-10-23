-- Create a new user login
-- name: CreateUserLogin :one
INSERT INTO user_logins (user_id, login_at, ip_address, user_agent)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- Get all user logins with a limit
-- name: GetAllUserLogins :many
SELECT * FROM user_logins
LIMIT $1;

-- Get user logins by user ID
-- name: GetUserLoginsByUserID :many
SELECT * FROM user_logins
WHERE user_id = $1;

-- Update a user login
-- name: UpdateUserLogin :one
UPDATE user_logins
SET login_at = $1, ip_address = $2, user_agent = $3
WHERE id = $4
RETURNING *;

-- Delete a user login
-- name: DeleteUserLogin :exec
DELETE FROM user_logins
WHERE id = $1;