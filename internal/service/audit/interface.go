package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AuditService defines the interface for audit logging operations
type AuditService interface {
	// LogEvent logs an audit event with the provided details
	LogEvent(ctx context.Context, event AuditEvent) error

	// GetUserAuditLogs retrieves audit logs for a specific user with pagination
	GetUserAuditLogs(ctx context.Context, userID uuid.UUID, req GetAuditLogsRequest) (*GetAuditLogsResponse, error)

	// GetAuditLogsByAction retrieves audit logs filtered by action with pagination
	GetAuditLogsByAction(ctx context.Context, action string, req GetAuditLogsRequest) (*GetAuditLogsResponse, error)

	// GetAuditLogsByResource retrieves audit logs for a specific resource with pagination
	GetAuditLogsByResource(ctx context.Context, resourceType, resourceID string, req GetAuditLogsRequest) (*GetAuditLogsResponse, error)

	// GetAuditLogsByTimeRange retrieves audit logs within a time range with pagination
	GetAuditLogsByTimeRange(ctx context.Context, startTime, endTime time.Time, req GetAuditLogsRequest) (*GetAuditLogsResponse, error)

	// GetRecentAuditLogs retrieves the most recent audit logs with pagination
	GetRecentAuditLogs(ctx context.Context, req GetAuditLogsRequest) (*GetAuditLogsResponse, error)

	// GetAuditLogByID retrieves a specific audit log by ID
	GetAuditLogByID(ctx context.Context, id uuid.UUID) (*AuditLog, error)

	// CountAuditLogs returns the total count of audit logs
	CountAuditLogs(ctx context.Context) (int64, error)

	// CountUserAuditLogs returns the count of audit logs for a specific user
	CountUserAuditLogs(ctx context.Context, userID uuid.UUID) (int64, error)

	// CountAuditLogsByAction returns the count of audit logs for a specific action
	CountAuditLogsByAction(ctx context.Context, action string) (int64, error)

	// CleanupOldLogs removes audit logs older than the specified time
	CleanupOldLogs(ctx context.Context, olderThan time.Time) error
}

// AuditRepository defines the interface for audit data access
type AuditRepository interface {
	// CreateAuditLog creates a new audit log entry
	CreateAuditLog(ctx context.Context, params CreateAuditLogParams) (*AuditLog, error)

	// GetAuditLogByID retrieves an audit log by ID
	GetAuditLogByID(ctx context.Context, id uuid.UUID) (*AuditLog, error)

	// GetUserAuditLogs retrieves audit logs for a user with pagination
	GetUserAuditLogs(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]*AuditLog, error)

	// GetAuditLogsByAction retrieves audit logs by action with pagination
	GetAuditLogsByAction(ctx context.Context, action string, limit, offset int32) ([]*AuditLog, error)

	// GetAuditLogsByResource retrieves audit logs by resource with pagination
	GetAuditLogsByResource(ctx context.Context, resourceType, resourceID string, limit, offset int32) ([]*AuditLog, error)

	// GetAuditLogsByTimeRange retrieves audit logs within time range with pagination
	GetAuditLogsByTimeRange(ctx context.Context, startTime, endTime time.Time, limit, offset int32) ([]*AuditLog, error)

	// GetRecentAuditLogs retrieves recent audit logs with pagination
	GetRecentAuditLogs(ctx context.Context, limit, offset int32) ([]*AuditLog, error)

	// CountAuditLogs returns total count of audit logs
	CountAuditLogs(ctx context.Context) (int64, error)

	// CountUserAuditLogs returns count of audit logs for a user
	CountUserAuditLogs(ctx context.Context, userID uuid.UUID) (int64, error)

	// CountAuditLogsByAction returns count of audit logs for an action
	CountAuditLogsByAction(ctx context.Context, action string) (int64, error)

	// DeleteOldAuditLogs removes audit logs older than specified time
	DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) error
}
