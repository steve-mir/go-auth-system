-- name: GetPost :one
SELECT * FROM posts WHERE id = $1;

-- name: CreatePost :exec
INSERT INTO posts (id, content) VALUES ($1, $2);

-- name: ListPosts :many
SELECT * FROM posts;

-- name: DeletePost :exec
DELETE FROM posts WHERE id = $1;

-- name: GetComment :one
SELECT * FROM comments WHERE id = $1;

-- name: CreateComment :exec
INSERT INTO comments (postId, userId, content) VALUES ($1, $2, $3);

-- name: ListComments :many
SELECT * FROM comments;

-- name: DeleteComment :exec
DELETE FROM comments WHERE id = $1;