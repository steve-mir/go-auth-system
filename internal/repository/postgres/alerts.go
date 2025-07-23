package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
)

// AlertRepository implements the admin.AlertRepository interface using SQLC
type AlertRepository struct {
	queries *db.Queries
}

// NewAlertRepository creates a new alert repository using SQLC
func NewAlertRepository(queries *db.Queries) *AlertRepository {
	return &AlertRepository{
		queries: queries,
	}
}

// CreateAlert creates a new alert
func (r *AlertRepository) CreateAlert(ctx context.Context, alert *admin.Alert) error {
	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	params := db.CreateAlertParams{
		ID:         alert.ID,
		Type:       alert.Type,
		Severity:   alert.Severity,
		Title:      alert.Title,
		Message:    alert.Message,
		Source:     alert.Source,
		Metadata:   metadataJSON,
		CreatedAt:  pgtype.Timestamp{Time: alert.CreatedAt, Valid: true},
		UpdatedAt:  pgtype.Timestamp{Time: alert.UpdatedAt, Valid: true},
		IsActive:   pgtype.Bool{Bool: alert.IsActive, Valid: true},
		IsResolved: pgtype.Bool{Bool: alert.IsResolved, Valid: true},
	}

	_, err = r.queries.CreateAlert(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to create alert: %w", err)
	}

	return nil
}

// GetAlertByID retrieves an alert by ID
func (r *AlertRepository) GetAlertByID(ctx context.Context, alertID uuid.UUID) (*admin.Alert, error) {
	dbAlert, err := r.queries.GetAlertByID(ctx, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to get alert: %w", err)
	}

	return r.convertDBAlertToAdmin(&dbAlert)
}

// GetActiveAlerts retrieves all active alerts
func (r *AlertRepository) GetActiveAlerts(ctx context.Context) ([]admin.Alert, error) {
	dbAlerts, err := r.queries.GetActiveAlerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active alerts: %w", err)
	}

	alerts := make([]admin.Alert, len(dbAlerts))
	for i, dbAlert := range dbAlerts {
		alert, err := r.convertDBAlertToAdmin(&dbAlert)
		if err != nil {
			return nil, fmt.Errorf("failed to convert alert %d: %w", i, err)
		}
		alerts[i] = *alert
	}

	return alerts, nil
}

// GetAlerts retrieves alerts with pagination and filtering
func (r *AlertRepository) GetAlerts(ctx context.Context, req *admin.GetAlertsRequest) ([]admin.Alert, int64, error) {
	// Get total count
	countParams := db.CountAlertsParams{
		Column1: req.Type,
		Column2: req.Severity,
		Column3: req.Source,
		Column4: req.IsActive != nil && *req.IsActive,
	}

	total, err := r.queries.CountAlerts(ctx, countParams)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get alerts count: %w", err)
	}

	// Get alerts
	offset := (req.Page - 1) * req.Limit
	getParams := db.GetAlertsParams{
		Column1: req.Type,
		Column2: req.Severity,
		Column3: req.Source,
		Column4: req.IsActive != nil && *req.IsActive,
		Column5: req.SortBy,
		Limit:   int32(req.Limit),
		Offset:  int32(offset),
	}

	dbAlerts, err := r.queries.GetAlerts(ctx, getParams)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get alerts: %w", err)
	}

	alerts := make([]admin.Alert, len(dbAlerts))
	for i, dbAlert := range dbAlerts {
		alert, err := r.convertDBAlertToAdmin(&dbAlert)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to convert alert %d: %w", i, err)
		}
		alerts[i] = *alert
	}

	return alerts, total, nil
}

// UpdateAlert updates an existing alert
func (r *AlertRepository) UpdateAlert(ctx context.Context, alert *admin.Alert) error {
	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var resolvedAt pgtype.Timestamp
	if alert.ResolvedAt != nil {
		resolvedAt = pgtype.Timestamp{Time: *alert.ResolvedAt, Valid: true}
	}

	params := db.UpdateAlertParams{
		ID:         alert.ID,
		Type:       alert.Type,
		Severity:   alert.Severity,
		Title:      alert.Title,
		Message:    alert.Message,
		Source:     alert.Source,
		Metadata:   metadataJSON,
		UpdatedAt:  pgtype.Timestamp{Time: alert.UpdatedAt, Valid: true},
		ResolvedAt: resolvedAt,
		IsActive:   pgtype.Bool{Bool: alert.IsActive, Valid: true},
		IsResolved: pgtype.Bool{Bool: alert.IsResolved, Valid: true},
	}

	err = r.queries.UpdateAlert(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to update alert: %w", err)
	}

	return nil
}

// DeleteAlert deletes an alert
func (r *AlertRepository) DeleteAlert(ctx context.Context, alertID uuid.UUID) error {
	err := r.queries.DeleteAlert(ctx, alertID)
	if err != nil {
		return fmt.Errorf("failed to delete alert: %w", err)
	}
	return nil
}

// GetAlertsByType retrieves alerts by type
func (r *AlertRepository) GetAlertsByType(ctx context.Context, alertType string) ([]admin.Alert, error) {
	// Use GetAlerts with type filter since GetAlertsByType is not generated
	params := db.GetAlertsParams{
		Column1: alertType,
		Column2: "",
		Column3: "",
		Column4: false,
		Column5: "created_at",
		Limit:   1000, // Large limit to get all
		Offset:  0,
	}

	dbAlerts, err := r.queries.GetAlerts(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts by type: %w", err)
	}

	alerts := make([]admin.Alert, len(dbAlerts))
	for i, dbAlert := range dbAlerts {
		alert, err := r.convertDBAlertToAdmin(&dbAlert)
		if err != nil {
			return nil, fmt.Errorf("failed to convert alert %d: %w", i, err)
		}
		alerts[i] = *alert
	}

	return alerts, nil
}

// GetAlertsBySeverity retrieves alerts by severity
func (r *AlertRepository) GetAlertsBySeverity(ctx context.Context, severity string) ([]admin.Alert, error) {
	dbAlerts, err := r.queries.GetAlertsBySeverity(ctx, severity)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts by severity: %w", err)
	}

	alerts := make([]admin.Alert, len(dbAlerts))
	for i, dbAlert := range dbAlerts {
		alert, err := r.convertDBAlertToAdmin(&dbAlert)
		if err != nil {
			return nil, fmt.Errorf("failed to convert alert %d: %w", i, err)
		}
		alerts[i] = *alert
	}

	return alerts, nil
}

// MarkAlertResolved marks an alert as resolved
func (r *AlertRepository) MarkAlertResolved(ctx context.Context, alertID uuid.UUID) error {
	now := time.Now()
	params := db.MarkAlertResolvedParams{
		ID:         alertID,
		ResolvedAt: pgtype.Timestamp{Time: now, Valid: true},
	}

	err := r.queries.MarkAlertResolved(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to mark alert as resolved: %w", err)
	}

	return nil
}

// convertDBAlertToAdmin converts a database alert to admin alert
func (r *AlertRepository) convertDBAlertToAdmin(dbAlert *db.Alert) (*admin.Alert, error) {
	alert := &admin.Alert{
		ID:         dbAlert.ID,
		Type:       dbAlert.Type,
		Severity:   dbAlert.Severity,
		Title:      dbAlert.Title,
		Message:    dbAlert.Message,
		Source:     dbAlert.Source,
		IsActive:   dbAlert.IsActive.Bool,
		IsResolved: dbAlert.IsResolved.Bool,
	}

	if dbAlert.CreatedAt.Valid {
		alert.CreatedAt = dbAlert.CreatedAt.Time
	}

	if dbAlert.UpdatedAt.Valid {
		alert.UpdatedAt = dbAlert.UpdatedAt.Time
	}

	if dbAlert.ResolvedAt.Valid {
		alert.ResolvedAt = &dbAlert.ResolvedAt.Time
	}

	if len(dbAlert.Metadata) > 0 {
		if err := json.Unmarshal(dbAlert.Metadata, &alert.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return alert, nil
}
