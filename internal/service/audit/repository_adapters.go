package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// postgresRepository implements the AuditRepository interface using SQLC generated code
type postgresRepository struct {
	queries *db.Queries
}

// NewPostgresRepository creates a new PostgreSQL audit repository
func NewPostgresRepository(queries *db.Queries) AuditRepository {
	return &postgresRepository{
		queries: queries,
	}
}

// CreateAuditLog creates a new audit log entry
func (r *postgresRepository) CreateAuditLog(ctx context.Context, params interfaces.CreateAuditLogParams) (*interfaces.AuditLog, error) {
	// Convert metadata to JSON
	var metadataJSON json.RawMessage
	if params.Metadata != nil {
		data, err := json.Marshal(params.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = data
	} else {
		metadataJSON = json.RawMessage("{}")
	}

	// Convert parameters to SQLC format
	sqlcParams := db.CreateAuditLogParams{
		UserID:   params.UserID,
		Action:   params.Action,
		Metadata: metadataJSON,
	}

	// Set optional fields
	if params.ResourceType != "" {
		sqlcParams.ResourceType = pgtype.Text{String: params.ResourceType, Valid: true}
	}
	if params.ResourceID != "" {
		sqlcParams.ResourceID = pgtype.Text{String: params.ResourceID, Valid: true}
	}
	if params.IPAddress != nil {
		sqlcParams.IpAddress = params.IPAddress
	}
	if params.UserAgent != "" {
		sqlcParams.UserAgent = pgtype.Text{String: params.UserAgent, Valid: true}
	}

	// Create audit log
	dbAuditLog, err := r.queries.CreateAuditLog(ctx, sqlcParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	// Convert to service model
	auditLog, err := r.convertFromDB(dbAuditLog)
	if err != nil {
		return nil, fmt.Errorf("failed to convert audit log: %w", err)
	}

	return auditLog, nil
}

// GetAuditLogByID retrieves an audit log by ID
func (r *postgresRepository) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*interfaces.AuditLog, error) {
	dbAuditLog, err := r.queries.GetAuditLogByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log by ID: %w", err)
	}

	auditLog, err := r.convertFromDB(dbAuditLog)
	if err != nil {
		return nil, fmt.Errorf("failed to convert audit log: %w", err)
	}

	return auditLog, nil
}

// GetUserAuditLogs retrieves audit logs for a user with pagination
func (r *postgresRepository) GetUserAuditLogs(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]*interfaces.AuditLog, error) {
	params := db.GetUserAuditLogsParams{
		UserID: userID,
		Limit:  limit,
		Offset: offset,
	}

	dbAuditLogs, err := r.queries.GetUserAuditLogs(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get user audit logs: %w", err)
	}

	auditLogs := make([]*interfaces.AuditLog, len(dbAuditLogs))
	for i, dbLog := range dbAuditLogs {
		auditLog, err := r.convertFromDB(dbLog)
		if err != nil {
			return nil, fmt.Errorf("failed to convert audit log at index %d: %w", i, err)
		}
		auditLogs[i] = auditLog
	}

	return auditLogs, nil
}

// GetAuditLogsByAction retrieves audit logs by action with pagination
func (r *postgresRepository) GetAuditLogsByAction(ctx context.Context, action string, limit, offset int32) ([]*interfaces.AuditLog, error) {
	params := db.GetAuditLogsByActionParams{
		Action: action,
		Limit:  limit,
		Offset: offset,
	}

	dbAuditLogs, err := r.queries.GetAuditLogsByAction(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs by action: %w", err)
	}

	auditLogs := make([]*interfaces.AuditLog, len(dbAuditLogs))
	for i, dbLog := range dbAuditLogs {
		auditLog, err := r.convertFromDB(dbLog)
		if err != nil {
			return nil, fmt.Errorf("failed to convert audit log at index %d: %w", i, err)
		}
		auditLogs[i] = auditLog
	}

	return auditLogs, nil
}

// GetAuditLogsByResource retrieves audit logs by resource with pagination
func (r *postgresRepository) GetAuditLogsByResource(ctx context.Context, resourceType, resourceID string, limit, offset int32) ([]*interfaces.AuditLog, error) {
	params := db.GetAuditLogsByResourceParams{
		ResourceType: pgtype.Text{String: resourceType, Valid: true},
		ResourceID:   pgtype.Text{String: resourceID, Valid: true},
		Limit:        limit,
		Offset:       offset,
	}

	dbAuditLogs, err := r.queries.GetAuditLogsByResource(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs by resource: %w", err)
	}

	auditLogs := make([]*interfaces.AuditLog, len(dbAuditLogs))
	for i, dbLog := range dbAuditLogs {
		auditLog, err := r.convertFromDB(dbLog)
		if err != nil {
			return nil, fmt.Errorf("failed to convert audit log at index %d: %w", i, err)
		}
		auditLogs[i] = auditLog
	}

	return auditLogs, nil
}

// GetAuditLogsByTimeRange retrieves audit logs within time range with pagination
func (r *postgresRepository) GetAuditLogsByTimeRange(ctx context.Context, startTime, endTime time.Time, limit, offset int32) ([]*interfaces.AuditLog, error) {
	params := db.GetAuditLogsByTimeRangeParams{
		Timestamp:   pgtype.Timestamp{Time: startTime, Valid: true},
		Timestamp_2: pgtype.Timestamp{Time: endTime, Valid: true},
		Limit:       limit,
		Offset:      offset,
	}

	dbAuditLogs, err := r.queries.GetAuditLogsByTimeRange(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs by time range: %w", err)
	}

	auditLogs := make([]*interfaces.AuditLog, len(dbAuditLogs))
	for i, dbLog := range dbAuditLogs {
		auditLog, err := r.convertFromDB(dbLog)
		if err != nil {
			return nil, fmt.Errorf("failed to convert audit log at index %d: %w", i, err)
		}
		auditLogs[i] = auditLog
	}

	return auditLogs, nil
}

// GetRecentAuditLogs retrieves recent audit logs with pagination
func (r *postgresRepository) GetRecentAuditLogs(ctx context.Context, limit, offset int32) ([]*interfaces.AuditLog, error) {
	params := db.GetRecentAuditLogsParams{
		Limit:  limit,
		Offset: offset,
	}

	dbAuditLogs, err := r.queries.GetRecentAuditLogs(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent audit logs: %w", err)
	}

	auditLogs := make([]*interfaces.AuditLog, len(dbAuditLogs))
	for i, dbLog := range dbAuditLogs {
		auditLog, err := r.convertFromDB(dbLog)
		if err != nil {
			return nil, fmt.Errorf("failed to convert audit log at index %d: %w", i, err)
		}
		auditLogs[i] = auditLog
	}

	return auditLogs, nil
}

// CountAuditLogs returns total count of audit logs
func (r *postgresRepository) CountAuditLogs(ctx context.Context) (int64, error) {
	count, err := r.queries.CountAuditLogs(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	return count, nil
}

// CountUserAuditLogs returns count of audit logs for a user
func (r *postgresRepository) CountUserAuditLogs(ctx context.Context, userID uuid.UUID) (int64, error) {
	count, err := r.queries.CountUserAuditLogs(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to count user audit logs: %w", err)
	}
	return count, nil
}

// CountAuditLogsByAction returns count of audit logs for an action
func (r *postgresRepository) CountAuditLogsByAction(ctx context.Context, action string) (int64, error) {
	count, err := r.queries.CountAuditLogsByAction(ctx, action)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs by action: %w", err)
	}
	return count, nil
}

// DeleteOldAuditLogs removes audit logs older than specified time
func (r *postgresRepository) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) error {
	timestamp := pgtype.Timestamp{Time: olderThan, Valid: true}
	err := r.queries.DeleteOldAuditLogs(ctx, timestamp)
	if err != nil {
		return fmt.Errorf("failed to delete old audit logs: %w", err)
	}
	return nil
}

// convertFromDB converts a database audit log to service model
func (r *postgresRepository) convertFromDB(dbLog db.AuditLog) (*interfaces.AuditLog, error) {
	auditLog := &interfaces.AuditLog{
		ID:     dbLog.ID,
		UserID: dbLog.UserID,
		Action: dbLog.Action,
	}

	// Convert optional fields
	if dbLog.ResourceType.Valid {
		auditLog.ResourceType = dbLog.ResourceType.String
	}
	if dbLog.ResourceID.Valid {
		auditLog.ResourceID = dbLog.ResourceID.String
	}
	if dbLog.IpAddress != nil {
		auditLog.IPAddress = dbLog.IpAddress
	}
	if dbLog.UserAgent.Valid {
		auditLog.UserAgent = dbLog.UserAgent.String
	}
	if dbLog.Timestamp.Valid {
		auditLog.Timestamp = dbLog.Timestamp.Time
	}

	// Convert metadata JSON to map
	if len(dbLog.Metadata) > 0 && string(dbLog.Metadata) != "{}" {
		var metadata map[string]interface{}
		if err := json.Unmarshal(dbLog.Metadata, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
		auditLog.Metadata = metadata
	} else {
		auditLog.Metadata = make(map[string]interface{})
	}

	return auditLog, nil
}
