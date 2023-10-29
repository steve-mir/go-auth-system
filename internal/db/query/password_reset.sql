-- name: CreatePasswordResetRequest :exec
INSERT INTO password_reset_requests (email, token, used, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetPasswordResetRequestByID :one
SELECT * FROM password_reset_requests WHERE id = $1 LIMIT 1;

-- name: GetPasswordResetRequestByToken :one
SELECT * FROM password_reset_requests WHERE token = $1 LIMIT 1;

-- name: UpdatePasswordResetRequest :exec
UPDATE password_reset_requests SET used = $1 WHERE id = $2;

-- name: UpdatePasswordResetRequestByToken :exec
UPDATE password_reset_requests SET used = $1 WHERE token = $2;

-- name: DeletePasswordResetRequestByID :exec
DELETE FROM password_reset_requests WHERE id = $1;
