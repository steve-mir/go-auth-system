-- name: CreateMFAConfig :one
INSERT INTO user_mfa (
    user_id, method, secret_encrypted, backup_codes_encrypted, enabled
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetMFAConfigByID :one
SELECT * FROM user_mfa WHERE id = $1;

-- name: GetUserMFAConfigs :many
SELECT * FROM user_mfa 
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: GetUserMFAByMethod :one
SELECT * FROM user_mfa 
WHERE user_id = $1 AND method = $2;

-- name: UpdateMFAConfig :one
UPDATE user_mfa SET
    secret_encrypted = COALESCE($2, secret_encrypted),
    backup_codes_encrypted = COALESCE($3, backup_codes_encrypted),
    enabled = COALESCE($4, enabled),
    last_used_at = CASE WHEN $5::boolean THEN NOW() ELSE last_used_at END
WHERE id = $1
RETURNING *;

-- name: EnableMFA :exec
UPDATE user_mfa SET
    enabled = true,
    last_used_at = NOW()
WHERE id = $1;

-- name: DisableMFA :exec
UPDATE user_mfa SET
    enabled = false
WHERE id = $1;

-- name: DeleteMFAConfig :exec
DELETE FROM user_mfa WHERE id = $1;

-- name: DeleteUserMFAConfigs :exec
DELETE FROM user_mfa WHERE user_id = $1;

-- name: GetEnabledMFAMethods :many
SELECT method FROM user_mfa 
WHERE user_id = $1 AND enabled = true
ORDER BY created_at ASC;

-- name: CountUserMFAMethods :one
SELECT COUNT(*) FROM user_mfa 
WHERE user_id = $1 AND enabled = true;