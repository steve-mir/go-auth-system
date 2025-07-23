package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// service implements the AuditService interface
type service struct {
	repo   AuditRepository
	logger *slog.Logger
}

// NewService creates a new audit service instance
func NewService(repo AuditRepository, logger *slog.Logger) AuditService {
	return &service{
		repo:   repo,
		logger: logger,
	}
}

// LogEvent logs an audit event with structured logging and database persistence
func convertAuditEventToCreateAuditLogParams(event AuditEvent) CreateAuditLogParams {
	return CreateAuditLogParams{
		UserID:       event.UserID,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		IPAddress:    event.IPAddress,
		UserAgent:    event.UserAgent,
		Metadata:     event.Metadata,
	}
}

// LogEvent logs an audit event with structured logging and database persistence
func (s *service) LogEvent(ctx context.Context, event AuditEvent) error {
	// Convert metadata to JSON
	metadataJSON, err := event.ToJSON()
	if err != nil {
		s.logger.Error("Failed to marshal audit event metadata",
			"error", err,
			"user_id", event.UserID,
			"action", event.Action)
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Example usage
	s.logger.Info("Audit event metadata",
		"metadata", metadataJSON,
		"user_id", event.UserID,
		"action", event.Action)

	// Create audit log parameters
	params := convertAuditEventToCreateAuditLogParams(event)

	// Persist to database
	auditLog, err := s.repo.CreateAuditLog(ctx, params)
	if err != nil {
		s.logger.Error("Failed to create audit log",
			"error", err,
			"user_id", event.UserID,
			"action", event.Action)
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	// Log structured event for monitoring and alerting
	s.logStructuredEvent(event, auditLog.ID)

	return nil
}

// GetUserAuditLogs retrieves audit logs for a specific user with pagination
func (s *service) GetUserAuditLogs(ctx context.Context, userID uuid.UUID, req GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	// Validate pagination parameters
	if err := s.validatePaginationRequest(req); err != nil {
		return nil, err
	}

	// Get audit logs
	logs, err := s.repo.GetUserAuditLogs(ctx, userID, req.Limit, req.Offset)
	if err != nil {
		s.logger.Error("Failed to get user audit logs",
			"error", err,
			"user_id", userID)
		return nil, fmt.Errorf("failed to get user audit logs: %w", err)
	}

	// Get total count
	totalCount, err := s.repo.CountUserAuditLogs(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to count user audit logs",
			"error", err,
			"user_id", userID)
		return nil, fmt.Errorf("failed to count user audit logs: %w", err)
	}

	return &GetAuditLogsResponse{
		AuditLogs:  logs,
		TotalCount: totalCount,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogsByAction retrieves audit logs filtered by action with pagination
func (s *service) GetAuditLogsByAction(ctx context.Context, action string, req GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	// Validate pagination parameters
	if err := s.validatePaginationRequest(req); err != nil {
		return nil, err
	}

	// Get audit logs
	logs, err := s.repo.GetAuditLogsByAction(ctx, action, req.Limit, req.Offset)
	if err != nil {
		s.logger.Error("Failed to get audit logs by action",
			"error", err,
			"action", action)
		return nil, fmt.Errorf("failed to get audit logs by action: %w", err)
	}

	// Get total count
	totalCount, err := s.repo.CountAuditLogsByAction(ctx, action)
	if err != nil {
		s.logger.Error("Failed to count audit logs by action",
			"error", err,
			"action", action)
		return nil, fmt.Errorf("failed to count audit logs by action: %w", err)
	}

	return &GetAuditLogsResponse{
		AuditLogs:  logs,
		TotalCount: totalCount,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogsByResource retrieves audit logs for a specific resource with pagination
func (s *service) GetAuditLogsByResource(ctx context.Context, resourceType, resourceID string, req GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	// Validate pagination parameters
	if err := s.validatePaginationRequest(req); err != nil {
		return nil, err
	}

	// Get audit logs
	logs, err := s.repo.GetAuditLogsByResource(ctx, resourceType, resourceID, req.Limit, req.Offset)
	if err != nil {
		s.logger.Error("Failed to get audit logs by resource",
			"error", err,
			"resource_type", resourceType,
			"resource_id", resourceID)
		return nil, fmt.Errorf("failed to get audit logs by resource: %w", err)
	}

	// For resource-specific queries, we don't have a direct count method
	// so we'll use the general count as an approximation
	totalCount, err := s.repo.CountAuditLogs(ctx)
	if err != nil {
		s.logger.Error("Failed to count audit logs",
			"error", err)
		return nil, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return &GetAuditLogsResponse{
		AuditLogs:  logs,
		TotalCount: totalCount,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogsByTimeRange retrieves audit logs within a time range with pagination
func (s *service) GetAuditLogsByTimeRange(ctx context.Context, startTime, endTime time.Time, req GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	// Validate time range
	if startTime.After(endTime) {
		return nil, fmt.Errorf("start time cannot be after end time")
	}

	// Validate pagination parameters
	if err := s.validatePaginationRequest(req); err != nil {
		return nil, err
	}

	// Get audit logs
	logs, err := s.repo.GetAuditLogsByTimeRange(ctx, startTime, endTime, req.Limit, req.Offset)
	if err != nil {
		s.logger.Error("Failed to get audit logs by time range",
			"error", err,
			"start_time", startTime,
			"end_time", endTime)
		return nil, fmt.Errorf("failed to get audit logs by time range: %w", err)
	}

	// For time range queries, we don't have a direct count method
	// so we'll use the general count as an approximation
	totalCount, err := s.repo.CountAuditLogs(ctx)
	if err != nil {
		s.logger.Error("Failed to count audit logs",
			"error", err)
		return nil, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return &GetAuditLogsResponse{
		AuditLogs:  logs,
		TotalCount: totalCount,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetRecentAuditLogs retrieves the most recent audit logs with pagination
func (s *service) GetRecentAuditLogs(ctx context.Context, req GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	// Validate pagination parameters
	if err := s.validatePaginationRequest(req); err != nil {
		return nil, err
	}

	// Get audit logs
	logs, err := s.repo.GetRecentAuditLogs(ctx, req.Limit, req.Offset)
	if err != nil {
		s.logger.Error("Failed to get recent audit logs",
			"error", err)
		return nil, fmt.Errorf("failed to get recent audit logs: %w", err)
	}

	// Get total count
	totalCount, err := s.repo.CountAuditLogs(ctx)
	if err != nil {
		s.logger.Error("Failed to count audit logs",
			"error", err)
		return nil, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return &GetAuditLogsResponse{
		AuditLogs:  logs,
		TotalCount: totalCount,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogByID retrieves a specific audit log by ID
func (s *service) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*AuditLog, error) {
	auditLog, err := s.repo.GetAuditLogByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get audit log by ID",
			"error", err,
			"audit_log_id", id)
		return nil, fmt.Errorf("failed to get audit log by ID: %w", err)
	}

	return auditLog, nil
}

// CountAuditLogs returns the total count of audit logs
func (s *service) CountAuditLogs(ctx context.Context) (int64, error) {
	count, err := s.repo.CountAuditLogs(ctx)
	if err != nil {
		s.logger.Error("Failed to count audit logs",
			"error", err)
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return count, nil
}

// CountUserAuditLogs returns the count of audit logs for a specific user
func (s *service) CountUserAuditLogs(ctx context.Context, userID uuid.UUID) (int64, error) {
	count, err := s.repo.CountUserAuditLogs(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to count user audit logs",
			"error", err,
			"user_id", userID)
		return 0, fmt.Errorf("failed to count user audit logs: %w", err)
	}

	return count, nil
}

// CountAuditLogsByAction returns the count of audit logs for a specific action
func (s *service) CountAuditLogsByAction(ctx context.Context, action string) (int64, error) {
	count, err := s.repo.CountAuditLogsByAction(ctx, action)
	if err != nil {
		s.logger.Error("Failed to count audit logs by action",
			"error", err,
			"action", action)
		return 0, fmt.Errorf("failed to count audit logs by action: %w", err)
	}

	return count, nil
}

// CleanupOldLogs removes audit logs older than the specified time
func (s *service) CleanupOldLogs(ctx context.Context, olderThan time.Time) error {
	err := s.repo.DeleteOldAuditLogs(ctx, olderThan)
	if err != nil {
		s.logger.Error("Failed to cleanup old audit logs",
			"error", err,
			"older_than", olderThan)
		return fmt.Errorf("failed to cleanup old audit logs: %w", err)
	}

	s.logger.Info("Successfully cleaned up old audit logs",
		"older_than", olderThan)

	return nil
}

// validatePaginationRequest validates pagination parameters
func (s *service) validatePaginationRequest(req GetAuditLogsRequest) error {
	if req.Limit <= 0 {
		return fmt.Errorf("limit must be greater than 0")
	}
	if req.Limit > 1000 {
		return fmt.Errorf("limit cannot exceed 1000")
	}
	if req.Offset < 0 {
		return fmt.Errorf("offset cannot be negative")
	}
	return nil
}

// logStructuredEvent logs the audit event with structured logging for monitoring
func (s *service) logStructuredEvent(event AuditEvent, auditLogID uuid.UUID) {
	logAttrs := []slog.Attr{
		slog.String("audit_log_id", auditLogID.String()),
		slog.String("user_id", event.UserID.String()),
		slog.String("action", event.Action),
	}

	if event.ResourceType != "" {
		logAttrs = append(logAttrs, slog.String("resource_type", event.ResourceType))
	}
	if event.ResourceID != "" {
		logAttrs = append(logAttrs, slog.String("resource_id", event.ResourceID))
	}
	if event.IPAddress != nil {
		logAttrs = append(logAttrs, slog.String("ip_address", event.IPAddress.String()))
	}
	if event.UserAgent != "" {
		logAttrs = append(logAttrs, slog.String("user_agent", event.UserAgent))
	}
	if event.Metadata != nil && len(event.Metadata) > 0 {
		metadataJSON, _ := json.Marshal(event.Metadata)
		logAttrs = append(logAttrs, slog.String("metadata", string(metadataJSON)))
	}

	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "Audit event logged", logAttrs...)
}
