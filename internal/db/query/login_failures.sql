-- Create a new login failure
-- name: CreateLoginFailure :one
INSERT INTO login_failures (email, timestamp, user_agent, ip_address)
VALUES ($1, $2, $3, $4) RETURNING *;

-- Get all login failures with a limit
-- name: GetAllLoginFailures :many
SELECT * FROM login_failures
LIMIT $1;

-- Get login failures by user ID
-- name: GetLoginFailuresByUserID :many
SELECT * FROM login_failures
WHERE email = $1;

-- Update a login failure
-- name: UpdateLoginFailure :one
UPDATE login_failures
SET timestamp = $1, user_agent = $2, ip_address = $3
WHERE id = $4 RETURNING *;

-- Delete a login failure
-- name: DeleteLoginFailure :exec
DELETE FROM login_failures
WHERE id = $1;