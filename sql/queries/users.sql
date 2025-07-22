-- name: CreateUser :one
INSERT INTO users (
    email, username, password_hash, hash_algorithm, 
    first_name_encrypted, last_name_encrypted, phone_encrypted
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: UpdateUser :one
UPDATE users SET
    email = COALESCE($2, email),
    username = COALESCE($3, username),
    password_hash = COALESCE($4, password_hash),
    hash_algorithm = COALESCE($5, hash_algorithm),
    first_name_encrypted = COALESCE($6, first_name_encrypted),
    last_name_encrypted = COALESCE($7, last_name_encrypted),
    phone_encrypted = COALESCE($8, phone_encrypted),
    email_verified = COALESCE($9, email_verified),
    phone_verified = COALESCE($10, phone_verified),
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateUserLoginInfo :exec
UPDATE users SET
    failed_login_attempts = $2,
    account_locked = $3,
    last_login_at = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: GetUsersByRole :many
SELECT u.* FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE r.name = $1
ORDER BY u.created_at DESC;