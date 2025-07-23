-- name: CreateSocialAccount :one
INSERT INTO social_accounts (
    id, user_id, provider, social_id, email, name, access_token, refresh_token, expires_at, metadata, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
) RETURNING *;

-- name: GetSocialAccountByProviderAndSocialID :one
SELECT * FROM social_accounts
WHERE provider = $1 AND social_id = $2;

-- name: GetSocialAccountsByUserID :many
SELECT * FROM social_accounts
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: GetSocialAccountByUserIDAndProvider :one
SELECT * FROM social_accounts
WHERE user_id = $1 AND provider = $2;

-- name: UpdateSocialAccount :exec
UPDATE social_accounts
SET email = $3, name = $4, access_token = $5, refresh_token = $6, expires_at = $7, metadata = $8, updated_at = $9
WHERE user_id = $1 AND provider = $2;

-- name: DeleteSocialAccount :exec
DELETE FROM social_accounts WHERE user_id = $1 AND provider = $2;

-- name: DeleteAllUserSocialAccounts :exec
DELETE FROM social_accounts WHERE user_id = $1;