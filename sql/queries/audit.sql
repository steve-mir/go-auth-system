-- name: CreateAuditLog :one
INSERT INTO audit_logs (
    user_id, action, resource_type, resource_id, ip_address, user_agent, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: GetAuditLogByID :one
SELECT * FROM audit_logs WHERE id = $1;

-- name: GetUserAuditLogs :many
SELECT * FROM audit_logs 
WHERE user_id = $1
ORDER BY timestamp DESC
LIMIT $2 OFFSET $3;

-- name: GetAuditLogsByAction :many
SELECT * FROM audit_logs 
WHERE action = $1
ORDER BY timestamp DESC
LIMIT $2 OFFSET $3;

-- name: GetAuditLogsByResource :many
SELECT * FROM audit_logs 
WHERE resource_type = $1 AND resource_id = $2
ORDER BY timestamp DESC
LIMIT $3 OFFSET $4;

-- name: GetAuditLogsByTimeRange :many
SELECT * FROM audit_logs 
WHERE timestamp >= $1 AND timestamp <= $2
ORDER BY timestamp DESC
LIMIT $3 OFFSET $4;

-- name: GetAuditLogsByUserAndAction :many
SELECT * FROM audit_logs 
WHERE user_id = $1 AND action = $2
ORDER BY timestamp DESC
LIMIT $3 OFFSET $4;

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM audit_logs;

-- name: CountUserAuditLogs :one
SELECT COUNT(*) FROM audit_logs WHERE user_id = $1;

-- name: CountAuditLogsByAction :one
SELECT COUNT(*) FROM audit_logs WHERE action = $1;

-- name: GetRecentAuditLogs :many
SELECT * FROM audit_logs 
ORDER BY timestamp DESC
LIMIT $1 OFFSET $2;

-- name: DeleteOldAuditLogs :exec
DELETE FROM audit_logs 
WHERE timestamp < $1;