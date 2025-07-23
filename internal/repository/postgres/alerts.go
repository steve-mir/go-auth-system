package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
)

// AlertRepository implements the admin.AlertRepository interface
type AlertRepository struct {
	db *sql.DB
}

// NewAlertRepository creates a new alert repository
func NewAlertRepository(db *sql.DB) *AlertRepository {
	return &AlertRepository{
		db: db,
	}
}

// CreateAlert creates a new alert
func (r *AlertRepository) CreateAlert(ctx context.Context, alert *admin.Alert) error {
	query := `
		INSERT INTO alerts (id, type, severity, title, message, source, metadata, created_at, updated_at, is_active, is_resolved)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		alert.ID,
		alert.Type,
		alert.Severity,
		alert.Title,
		alert.Message,
		alert.Source,
		metadataJSON,
		alert.CreatedAt,
		alert.UpdatedAt,
		alert.IsActive,
		alert.IsResolved,
	)

	if err != nil {
		return fmt.Errorf("failed to create alert: %w", err)
	}

	return nil
}

// GetAlertByID retrieves an alert by ID
func (r *AlertRepository) GetAlertByID(ctx context.Context, alertID uuid.UUID) (*admin.Alert, error) {
	query := `
		SELECT id, type, severity, title, message, source, metadata, created_at, updated_at, resolved_at, is_active, is_resolved
		FROM alerts
		WHERE id = $1
	`

	var alert admin.Alert
	var metadataJSON []byte
	var resolvedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, alertID).Scan(
		&alert.ID,
		&alert.Type,
		&alert.Severity,
		&alert.Title,
		&alert.Message,
		&alert.Source,
		&metadataJSON,
		&alert.CreatedAt,
		&alert.UpdatedAt,
		&resolvedAt,
		&alert.IsActive,
		&alert.IsResolved,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("alert not found")
		}
		return nil, fmt.Errorf("failed to get alert: %w", err)
	}

	if resolvedAt.Valid {
		alert.ResolvedAt = &resolvedAt.Time
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &alert, nil
}

// GetActiveAlerts retrieves all active alerts
func (r *AlertRepository) GetActiveAlerts(ctx context.Context) ([]admin.Alert, error) {
	query := `
		SELECT id, type, severity, title, message, source, metadata, created_at, updated_at, resolved_at, is_active, is_resolved
		FROM alerts
		WHERE is_active = true AND is_resolved = false
		ORDER BY severity DESC, created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active alerts: %w", err)
	}
	defer rows.Close()

	var alerts []admin.Alert
	for rows.Next() {
		var alert admin.Alert
		var metadataJSON []byte
		var resolvedAt sql.NullTime

		err := rows.Scan(
			&alert.ID,
			&alert.Type,
			&alert.Severity,
			&alert.Title,
			&alert.Message,
			&alert.Source,
			&metadataJSON,
			&alert.CreatedAt,
			&alert.UpdatedAt,
			&resolvedAt,
			&alert.IsActive,
			&alert.IsResolved,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		alerts = append(alerts, alert)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alerts: %w", err)
	}

	return alerts, nil
}

// GetAlerts retrieves alerts with pagination and filtering
func (r *AlertRepository) GetAlerts(ctx context.Context, req *admin.GetAlertsRequest) ([]admin.Alert, int64, error) {
	baseQuery := `
		SELECT id, type, severity, title, message, source, metadata, created_at, updated_at, resolved_at, is_active, is_resolved
		FROM alerts
	`

	countQuery := `SELECT COUNT(*) FROM alerts`

	var conditions []string
	var args []interface{}
	argIndex := 1

	// Add filters
	if req.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIndex))
		args = append(args, req.Type)
		argIndex++
	}

	if req.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIndex))
		args = append(args, req.Severity)
		argIndex++
	}

	if req.Source != "" {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argIndex))
		args = append(args, req.Source)
		argIndex++
	}

	if req.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *req.IsActive)
		argIndex++
	}

	// Add WHERE clause if conditions exist
	if len(conditions) > 0 {
		whereClause := " WHERE " + strings.Join(conditions, " AND ")
		baseQuery += whereClause
		countQuery += whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get alerts count: %w", err)
	}

	// Add sorting
	sortBy := "created_at"
	if req.SortBy != "" {
		switch req.SortBy {
		case "created_at", "updated_at", "severity", "type":
			sortBy = req.SortBy
		}
	}

	sortOrder := "DESC"
	if req.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	baseQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

	// Add pagination
	offset := (req.Page - 1) * req.Limit
	baseQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, req.Limit, offset)

	// Execute query
	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []admin.Alert
	for rows.Next() {
		var alert admin.Alert
		var metadataJSON []byte
		var resolvedAt sql.NullTime

		err := rows.Scan(
			&alert.ID,
			&alert.Type,
			&alert.Severity,
			&alert.Title,
			&alert.Message,
			&alert.Source,
			&metadataJSON,
			&alert.CreatedAt,
			&alert.UpdatedAt,
			&resolvedAt,
			&alert.IsActive,
			&alert.IsResolved,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan alert: %w", err)
		}

		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		alerts = append(alerts, alert)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating alerts: %w", err)
	}

	return alerts, total, nil
}

// UpdateAlert updates an existing alert
func (r *AlertRepository) UpdateAlert(ctx context.Context, alert *admin.Alert) error {
	query := `
		UPDATE alerts 
		SET type = $2, severity = $3, title = $4, message = $5, source = $6, metadata = $7, 
		    updated_at = $8, resolved_at = $9, is_active = $10, is_resolved = $11
		WHERE id = $1
	`

	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var resolvedAt interface{}
	if alert.ResolvedAt != nil {
		resolvedAt = *alert.ResolvedAt
	}

	result, err := r.db.ExecContext(ctx, query,
		alert.ID,
		alert.Type,
		alert.Severity,
		alert.Title,
		alert.Message,
		alert.Source,
		metadataJSON,
		alert.UpdatedAt,
		resolvedAt,
		alert.IsActive,
		alert.IsResolved,
	)

	if err != nil {
		return fmt.Errorf("failed to update alert: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("alert not found")
	}

	return nil
}

// DeleteAlert deletes an alert
func (r *AlertRepository) DeleteAlert(ctx context.Context, alertID uuid.UUID) error {
	query := `DELETE FROM alerts WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, alertID)
	if err != nil {
		return fmt.Errorf("failed to delete alert: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("alert not found")
	}

	return nil
}

// GetAlertsByType retrieves alerts by type
func (r *AlertRepository) GetAlertsByType(ctx context.Context, alertType string) ([]admin.Alert, error) {
	query := `
		SELECT id, type, severity, title, message, source, metadata, created_at, updated_at, resolved_at, is_active, is_resolved
		FROM alerts
		WHERE type = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, alertType)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts by type: %w", err)
	}
	defer rows.Close()

	var alerts []admin.Alert
	for rows.Next() {
		var alert admin.Alert
		var metadataJSON []byte
		var resolvedAt sql.NullTime

		err := rows.Scan(
			&alert.ID,
			&alert.Type,
			&alert.Severity,
			&alert.Title,
			&alert.Message,
			&alert.Source,
			&metadataJSON,
			&alert.CreatedAt,
			&alert.UpdatedAt,
			&resolvedAt,
			&alert.IsActive,
			&alert.IsResolved,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		alerts = append(alerts, alert)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alerts: %w", err)
	}

	return alerts, nil
}

// GetAlertsBySeverity retrieves alerts by severity
func (r *AlertRepository) GetAlertsBySeverity(ctx context.Context, severity string) ([]admin.Alert, error) {
	query := `
		SELECT id, type, severity, title, message, source, metadata, created_at, updated_at, resolved_at, is_active, is_resolved
		FROM alerts
		WHERE severity = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, severity)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts by severity: %w", err)
	}
	defer rows.Close()

	var alerts []admin.Alert
	for rows.Next() {
		var alert admin.Alert
		var metadataJSON []byte
		var resolvedAt sql.NullTime

		err := rows.Scan(
			&alert.ID,
			&alert.Type,
			&alert.Severity,
			&alert.Title,
			&alert.Message,
			&alert.Source,
			&metadataJSON,
			&alert.CreatedAt,
			&alert.UpdatedAt,
			&resolvedAt,
			&alert.IsActive,
			&alert.IsResolved,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		alerts = append(alerts, alert)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alerts: %w", err)
	}

	return alerts, nil
}

// MarkAlertResolved marks an alert as resolved
func (r *AlertRepository) MarkAlertResolved(ctx context.Context, alertID uuid.UUID) error {
	query := `
		UPDATE alerts 
		SET is_resolved = true, is_active = false, resolved_at = $2, updated_at = $2
		WHERE id = $1
	`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, alertID, now)
	if err != nil {
		return fmt.Errorf("failed to mark alert as resolved: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("alert not found")
	}

	return nil
}
