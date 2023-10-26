-- name: CreateUserProfile :exec
INSERT INTO user_profiles (
    user_id, first_name, last_name, phone, image_url
    )
VALUES ($1, $2, $3, $4, $5);

-- name: GetUserProfileByUID :one
SELECT * FROM user_profiles WHERE user_id = $1 LIMIT 1;


-- name: UpdateUserProfile :exec
UPDATE user_profiles
SET first_name = $2, last_name = $3
WHERE user_id = $1;

-- name: UpdateUserPhone :exec
UPDATE user_profiles
SET phone = $2
WHERE user_id = $1;

-- name: UpdateUserProfileImg :exec
UPDATE user_profiles
SET image_url = $2
WHERE user_id = $1;


-- name: DeleteUserProfileByID :exec
DELETE FROM user_profiles WHERE user_id = $1;