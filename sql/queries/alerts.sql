-- name: CreateAlert :one
INSERT INTO alerts (
    id, type, severity, title, message, source, metadata, created_at, updated_at, is_active, is_resolved
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
) RETURNING *;

-- name: GetAlertByID :one
SELECT * FROM alerts WHERE id = $1;

-- name: GetActiveAlerts :many
SELECT * FROM alerts
WHERE is_active = true AND is_resolved = false
ORDER BY severity DESC, created_at DESC;

-- name: GetAlerts :many
SELECT * FROM alerts
WHERE 
    ($1::text = '' OR type = $1) AND
    ($2::text = '' OR severity = $2) AND
    ($3::text = '' OR source = $3) AND
    ($4::boolean IS NULL OR is_active = $4)
ORDER BY 
    CASE WHEN $5 = 'created_at' THEN created_at END,
    CASE WHEN $5 = 'updated_at' THEN updated_at END,
    CASE WHEN $5 = 'severity' THEN severity END,
    CASE WHEN $5 = 'type' THEN type END
LIMIT $6 OFFSET $7;

-- name: CountAlerts :one
SELECT COUNT(*) FROM alerts
WHERE 
    ($1::text = '' OR type = $1) AND
    ($2::text = '' OR severity = $2) AND
    ($3::text = '' OR source = $3) AND
    ($4::boolean IS NULL OR is_active = $4);

-- name: UpdateAlert :exec
UPDATE alerts 
SET type = $2, severity = $3, title = $4, message = $5, source = $6, 
    metadata = $7, updated_at = $8, resolved_at = $9, is_active = $10, is_resolved = $11
WHERE id = $1;

-- name: DeleteAlert :exec
DELETE FROM alerts WHERE id = $1;

-- name: GetAlertsBySeverity :many
SELECT * FROM alerts
WHERE severity = $1
ORDER BY created_at DESC;

-- name: MarkAlertResolved :exec
UPDATE alerts 
SET is_resolved = true, is_active = false, resolved_at = $2, updated_at = $2
WHERE id = $1;

-- -- name: GetAlertsByType :many
-- SELECT * FROM alerts
-- WHERE type = $1
-- ORDER BY created_at DESC;