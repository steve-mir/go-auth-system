-- Create a new security question
-- name: CreateSecurityQuestion :one
INSERT INTO security_questions (user_id, question, answer, expired_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- Get all security questions with a limit
-- name: GetAllSecurityQuestions :many
SELECT * FROM security_questions
LIMIT $1;

-- Get security questions by user ID
-- name: GetSecurityQuestionsByUserID :many
SELECT * FROM security_questions
WHERE user_id = $1;

-- Update a security question
-- name: UpdateSecurityQuestion :one
UPDATE security_questions
SET question = $1, answer = $2, expired_at = $3
WHERE id = $4
RETURNING *;

-- Delete a security question
-- name: DeleteSecurityQuestion :exec
DELETE FROM security_questions
WHERE id = $1;