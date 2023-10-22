-- name: CreateUser :one
INSERT INTO users (id, name, email, username, password_hash, created_at, updated_at, last_login, is_suspended, is_deleted, login_attempts, lockout_duration, lockout_until, password_changed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: UpdateUser :one
UPDATE users
SET name = $2, email = $3, username = $4, password_hash = $5, updated_at = $6, last_login = $7, is_suspended = $8, is_deleted = $9, login_attempts = $10, lockout_duration = $11, lockout_until = $12
WHERE id = $1
RETURNING *;

-- name: DeleteUserByID :exec
DELETE FROM users WHERE id = $1;