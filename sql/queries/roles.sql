-- name: CreateRole :one
INSERT INTO roles (name, description, permissions)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetRoleByID :one
SELECT * FROM roles WHERE id = $1;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = $1;

-- name: UpdateRole :one
UPDATE roles SET
    name = COALESCE($2, name),
    description = COALESCE($3, description),
    permissions = COALESCE($4, permissions),
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = $1;

-- name: ListRoles :many
SELECT * FROM roles
ORDER BY name ASC
LIMIT $1 OFFSET $2;

-- name: CountRoles :one
SELECT COUNT(*) FROM roles;

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id, assigned_by)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: RemoveRoleFromUser :exec
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

-- name: GetUserRoles :many
SELECT r.* FROM roles r
JOIN user_roles ur ON r.id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.name ASC;

-- name: GetRoleUsers :many
SELECT u.* FROM users u
JOIN user_roles ur ON u.id = ur.user_id
WHERE ur.role_id = $1
ORDER BY u.created_at DESC;