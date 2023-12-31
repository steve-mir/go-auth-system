-- name: CreateUser :one
INSERT INTO users (
    id, name, email, username, password_hash, created_at,
    updated_at, is_suspended, is_deleted,
    login_attempts, lockout_duration, lockout_until,
    password_changed_at, is_verified
    )
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1 LIMIT 1;


-- name: UpdateUserOld :exec
UPDATE users
SET name = $2, email = $3, username = $4, password_hash = $5, updated_at = $6, is_suspended = $7, is_deleted = $8, login_attempts = $9, lockout_duration = $10, lockout_until = $11
WHERE id = $1;

-- name: UpdateUser :one
UPDATE users
SET
    name = COALESCE(sqlc.narg('name'), name),
    username = COALESCE(sqlc.narg('username'),username),
    email = COALESCE(sqlc.narg('email'),email),
    password_hash = COALESCE(sqlc.narg('password_hash'),password_hash),
    updated_at = COALESCE(sqlc.narg('updated_at'),updated_at),
    is_suspended = COALESCE(sqlc.narg('is_suspended'),is_suspended),
    is_deleted = COALESCE(sqlc.narg('is_deleted'),is_deleted),
    login_attempts = COALESCE(sqlc.narg('login_attempts'),login_attempts),
    lockout_duration = COALESCE(sqlc.narg('lockout_duration'),lockout_duration),
    lockout_until = COALESCE(sqlc.narg('lockout_until'),lockout_until),
    password_changed_at = COALESCE(sqlc.narg('password_changed_at'),password_changed_at),
    is_verified = COALESCE(sqlc.narg('is_verified'),is_verified)
WHERE
    id = sqlc.arg('id')
RETURNING *;


-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2
WHERE email = $1;

-- name: UpdateUserSuspension :exec
UPDATE users
SET is_suspended = $3, suspended_at = $2
WHERE id = $1;

-- name: UpdateUserEmailVerified :exec
UPDATE users
SET is_email_verified = $3,
email_verified_at = $2
WHERE id = $1;

-- name: DeleteUserByID :exec
DELETE FROM users WHERE id = $1;

-- name: GetUserAndRoleByID :one
SELECT users.*, user_roles.role_id
FROM users
JOIN user_roles ON users.id = user_roles.user_id
WHERE users.id = $1;