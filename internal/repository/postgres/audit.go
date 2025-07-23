package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// AuditRepository implements audit data access using SQLC
type AuditRepository struct {
	queries *db.Queries
}

// NewAuditRepository creates a new audit repository using SQLC
func NewAuditRepository(database *DB) *AuditRepository {
	return &AuditRepository{
		queries: db.New(database.Primary()),
	}
}

// LogEvent logs an audit event
func (r *AuditRepository) LogEvent(ctx context.Context, event *AuditLogData) error {
	params := db.CreateAuditLogParams{
		Action: event.Action,
		// TODO: set proper resource id and type
		ResourceID:   pgtype.Text{String: event.Resource, Valid: event.Resource != ""},
		ResourceType: pgtype.Text{String: event.Resource, Valid: event.Resource != ""},
		// IpAddress: event.IPAddress, TODO: Convert ip to ipnet
		UserAgent: pgtype.Text{String: event.UserAgent, Valid: event.UserAgent != ""},
		// Metadata:  event.Metadata, TODO: Convert.
	}

	// Set optional user ID
	if event.UserID != "" {
		userUUID, err := uuid.Parse(event.UserID)
		if err != nil {
			return fmt.Errorf("invalid user ID format: %w", err)
		}
		params.UserID = userUUID
	}

	_, err := r.queries.CreateAuditLog(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to log audit event: %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit logs with pagination and filtering
// func (r *AuditRepository) GetAuditLogs(ctx context.Context, filter *AuditLogFilter) ([]*AuditLogData, error) {
// 	params := db.ListAuditLogsParams{
// 		Limit:  filter.Limit,
// 		Offset: filter.Offset,
// 	}

// 	// Add optional filters
// 	if filter.UserID != "" {
// 		userUUID, err := uuid.Parse(filter.UserID)
// 		if err != nil {
// 			return nil, fmt.Errorf("invalid user ID format: %w", err)
// 		}
// 		params.UserID = pgtype.UUID{Bytes: userUUID, Valid: true}
// 	}

// 	if filter.Action != "" {
// 		params.Action = pgtype.Text{String: filter.Action, Valid: true}
// 	}

// 	if filter.Resource != "" {
// 		params.Resource = pgtype.Text{String: filter.Resource, Valid: true}
// 	}
// // TODO: Add query to sql
// 	logs, err := r.queries.ListAuditLogs(ctx, params)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get audit logs: %w", err)
// 	}

// 	result := make([]*AuditLogData, len(logs))
// 	for i, log := range logs {
// 		result[i] = r.convertToAuditLogData(log)
// 	}

// 	return result, nil
// }

// CountAuditLogs returns total number of audit logs matching filter
func (r *AuditRepository) CountAuditLogs(ctx context.Context, filter *AuditLogFilter) (int64, error) {
	// TODO: Add query to sql
	// params := db.CountAuditLogsParams{}

	// // Add optional filters
	// if filter.UserID != "" {
	// 	userUUID, err := uuid.Parse(filter.UserID)
	// 	if err != nil {
	// 		return 0, fmt.Errorf("invalid user ID format: %w", err)
	// 	}
	// 	params.UserID = pgtype.UUID{Bytes: userUUID, Valid: true}
	// }

	// if filter.Action != "" {
	// 	params.Action = pgtype.Text{String: filter.Action, Valid: true}
	// }

	// if filter.Resource != "" {
	// 	params.Resource = pgtype.Text{String: filter.Resource, Valid: true}
	// }

	count, err := r.queries.CountAuditLogs(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return count, nil
}

// GetAuditLogByID retrieves a specific audit log by ID
func (r *AuditRepository) GetAuditLogByID(ctx context.Context, logID string) (*AuditLogData, error) {
	id, err := uuid.Parse(logID)
	if err != nil {
		return nil, fmt.Errorf("invalid log ID format: %w", err)
	}

	log, err := r.queries.GetAuditLogByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}

	return r.convertToAuditLogData(log), nil
}

// convertToAuditLogData converts SQLC AuditLog model to service AuditLogData
func (r *AuditRepository) convertToAuditLogData(log db.AuditLog) *AuditLogData {
	// TODO: Fix comments
	auditData := &AuditLogData{
		ID:       log.ID.String(),
		Action:   log.Action,
		Resource: log.ResourceID.String,
		// Resource:  log.ResourceID.String,
		IPAddress: log.IpAddress.String(),
		UserAgent: log.UserAgent.String,
		// Metadata:  log.Metadata,
		// CreatedAt: log.CreatedAt.Time.Unix(),
	}

	// Handle optional user ID
	if log.UserID != uuid.Nil {
		auditData.UserID = log.UserID.String()
	}

	return auditData
}

// Data transfer objects for the repository layer
type AuditLogData struct {
	ID        string
	UserID    string
	Action    string
	Resource  string
	IPAddress string
	UserAgent string
	Metadata  map[string]interface{}
	CreatedAt int64
}

type AuditLogFilter struct {
	UserID   string
	Action   string
	Resource string
	Limit    int32
	Offset   int32
}
