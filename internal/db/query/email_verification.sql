-- name: CreateEmailVerificationRequest :exec
INSERT INTO email_verification_requests (user_id, email, token, is_verified, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetEmailVerificationRequestByID :one
SELECT * FROM email_verification_requests WHERE id = $1 LIMIT 1;

-- name: GetEmailVerificationRequestByToken :one
SELECT * FROM email_verification_requests WHERE token = $1 LIMIT 1;

-- name: UpdateEmailVerificationRequest :exec
UPDATE email_verification_requests SET is_verified = $1, expires_at = $2 WHERE id = $3;

-- name: UpdateByToken :exec
UPDATE email_verification_requests SET is_verified = $1 WHERE token = $2;

-- name: DeleteEmailVerificationRequestByID :exec
DELETE FROM email_verification_requests WHERE id = $1;
