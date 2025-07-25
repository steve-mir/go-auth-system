package admin

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// PostgresSessionRepository implements the SessionRepository interface using PostgreSQL
type PostgresSessionRepository struct {
	db    *postgres.DB
	store *db.Store
}

// NewPostgresSessionRepository creates a new PostgreSQL session repository
func NewPostgresSessionRepository(db *postgres.DB, store *db.Store) interfaces.SessionRepository {
	return &PostgresSessionRepository{
		db:    db,
		store: store,
	}
}

// GetAllSessions returns all user sessions with pagination
func (r *PostgresSessionRepository) GetAllSessions(ctx context.Context, req *interfaces.GetSessionsRequest) ([]interfaces.UserSession, int64, error) {
	limit := int32(req.Limit)
	offset := int32((req.Page - 1) * req.Limit)

	dbSessions, err := r.store.GetAllSessions(ctx, db.GetAllSessionsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, err
	}

	sessions := make([]interfaces.UserSession, len(dbSessions))
	for i, dbSession := range dbSessions {
		sessions[i] = interfaces.UserSession{
			SessionID: dbSession.ID,
			UserID:    dbSession.UserID,
			UserEmail: dbSession.Email,
			IPAddress: dbSession.IpAddress.String(),
			UserAgent: dbSession.UserAgent.String,
			CreatedAt: dbSession.CreatedAt.Time,
			LastUsed:  dbSession.LastUsedAt.Time,
			ExpiresAt: dbSession.ExpiresAt.Time,
			TokenType: dbSession.TokenType,
			IsActive:  dbSession.IsActive,
		}
	}

	// Get total count
	// total, err := r.store.CountAllSessions(ctx)
	// if err != nil {
	// 	return nil, 0, err
	// }

	return sessions, int64(len(sessions)), nil
}

// DeleteSession deletes a specific user session
func (r *PostgresSessionRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	return r.store.DeleteSession(ctx, sessionID)
}

// GetSessionByID retrieves a session by ID
func (r *PostgresSessionRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*interfaces.UserSession, error) {
	dbSession, err := r.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &interfaces.UserSession{
		SessionID: dbSession.ID,
		UserID:    dbSession.UserID,
		UserEmail: dbSession.Email,
		IPAddress: dbSession.IpAddress.String(),
		UserAgent: dbSession.UserAgent.String,
		CreatedAt: dbSession.CreatedAt.Time,
		LastUsed:  dbSession.LastUsedAt.Time,
		ExpiresAt: dbSession.ExpiresAt.Time,
		TokenType: dbSession.TokenType,
		IsActive:  dbSession.IsActive,
	}, nil
}

// GetUserSessions retrieves all sessions for a user
func (r *PostgresSessionRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]interfaces.UserSession, error) {
	dbSessions, err := r.store.GetUserSessions(ctx, db.GetUserSessionsParams{
		UserID: userID,
	})
	if err != nil {
		return nil, err
	}

	sessions := make([]interfaces.UserSession, len(dbSessions))
	for i, dbSession := range dbSessions {
		sessions[i] = interfaces.UserSession{
			SessionID: dbSession.ID,
			UserID:    dbSession.UserID,
			UserEmail: dbSession.Email,
			IPAddress: dbSession.IpAddress.String(),
			UserAgent: dbSession.UserAgent.String,
			CreatedAt: dbSession.CreatedAt.Time,
			LastUsed:  dbSession.LastUsedAt.Time,
			ExpiresAt: dbSession.ExpiresAt.Time,
			TokenType: dbSession.TokenType,
			IsActive:  dbSession.IsActive,
		}
	}

	return sessions, nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *PostgresSessionRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	return r.store.DeleteUserSessions(ctx, userID)
}

// GetActiveSessionsCount returns the count of active sessions
func (r *PostgresSessionRepository) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	return 0, nil
	// TODO: Implement
	// return r.store.CountActiveSessions(ctx)
}

// CleanupExpiredSessions removes expired sessions
func (r *PostgresSessionRepository) CleanupExpiredSessions(ctx context.Context) error {
	return r.store.CleanupExpiredSessions(ctx)
}

// PostgresAlertRepository implements the AlertRepository interface using PostgreSQL
type PostgresAlertRepository struct {
	db    *postgres.DB
	store *db.Store
}

// NewPostgresAlertRepository creates a new PostgreSQL alert repository
func NewPostgresAlertRepository(db *postgres.DB, store *db.Store) interfaces.AlertRepository {
	return &PostgresAlertRepository{
		db:    db,
		store: store,
	}
}

// CreateAlert creates a new alert
func (r *PostgresAlertRepository) CreateAlert(ctx context.Context, alert *interfaces.Alert) error {
	params := db.CreateAlertParams{
		ID:         alert.ID,
		Type:       alert.Type,
		Severity:   alert.Severity,
		Title:      alert.Title,
		Message:    alert.Message,
		Source:     alert.Source,
		IsActive:   pgtype.Bool{Bool: alert.IsActive, Valid: alert.IsActive},
		IsResolved: pgtype.Bool{Bool: alert.IsResolved, Valid: alert.IsResolved},
	}

	_, err := r.store.CreateAlert(ctx, params)
	return err
}

// GetAlertByID retrieves an alert by ID
func (r *PostgresAlertRepository) GetAlertByID(ctx context.Context, alertID uuid.UUID) (*interfaces.Alert, error) {
	dbAlert, err := r.store.GetAlertByID(ctx, alertID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	alert := &interfaces.Alert{
		ID:         dbAlert.ID,
		Type:       dbAlert.Type,
		Severity:   dbAlert.Severity,
		Title:      dbAlert.Title,
		Message:    dbAlert.Message,
		Source:     dbAlert.Source,
		CreatedAt:  dbAlert.CreatedAt.Time,
		UpdatedAt:  dbAlert.UpdatedAt.Time,
		IsActive:   dbAlert.IsActive.Bool,
		IsResolved: dbAlert.IsResolved.Bool,
	}

	if dbAlert.ResolvedAt.Valid {
		alert.ResolvedAt = &dbAlert.ResolvedAt.Time
	}

	return alert, nil
}

// GetActiveAlerts retrieves all active alerts
func (r *PostgresAlertRepository) GetActiveAlerts(ctx context.Context) ([]interfaces.Alert, error) {
	dbAlerts, err := r.store.GetActiveAlerts(ctx)
	if err != nil {
		return nil, err
	}

	alerts := make([]interfaces.Alert, len(dbAlerts))
	for i, dbAlert := range dbAlerts {
		alerts[i] = interfaces.Alert{
			ID:         dbAlert.ID,
			Type:       dbAlert.Type,
			Severity:   dbAlert.Severity,
			Title:      dbAlert.Title,
			Message:    dbAlert.Message,
			Source:     dbAlert.Source,
			CreatedAt:  dbAlert.CreatedAt.Time,
			UpdatedAt:  dbAlert.UpdatedAt.Time,
			IsActive:   dbAlert.IsActive.Bool,
			IsResolved: dbAlert.IsResolved.Bool,
		}

		if dbAlert.ResolvedAt.Valid {
			alerts[i].ResolvedAt = &dbAlert.ResolvedAt.Time
		}
	}

	return alerts, nil
}

// GetAlerts retrieves alerts with filtering and pagination
func (r *PostgresAlertRepository) GetAlerts(ctx context.Context, req *interfaces.GetAlertsRequest) ([]interfaces.Alert, int64, error) {
	// For now, return active alerts - implement filtering later
	alerts, err := r.GetActiveAlerts(ctx)
	if err != nil {
		return nil, 0, err
	}

	return alerts, int64(len(alerts)), nil
}

// UpdateAlert updates an existing alert
func (r *PostgresAlertRepository) UpdateAlert(ctx context.Context, alert *interfaces.Alert) error {
	params := db.UpdateAlertParams{
		ID:         alert.ID,
		Severity:   alert.Severity,
		Title:      alert.Title,
		Message:    alert.Message,
		IsActive:   pgtype.Bool{Bool: alert.IsActive, Valid: alert.IsActive},
		IsResolved: pgtype.Bool{Bool: alert.IsResolved, Valid: alert.IsResolved},
	}

	err := r.store.UpdateAlert(ctx, params)
	return err
}

// DeleteAlert deletes an alert
func (r *PostgresAlertRepository) DeleteAlert(ctx context.Context, alertID uuid.UUID) error {
	return r.store.DeleteAlert(ctx, alertID)
}

// GetAlertsByType retrieves alerts by type
func (r *PostgresAlertRepository) GetAlertsByType(ctx context.Context, alertType string) ([]interfaces.Alert, error) {
	return nil, nil
	// TODO: Implement:
	// dbAlerts, err := r.store.GetAlertsByType(ctx, alertType)
	// if err != nil {
	// 	return nil, err
	// }

	// alerts := make([]interfaces.Alert, len(dbAlerts))
	// for i, dbAlert := range dbAlerts {
	// 	alerts[i] = interfaces.Alert{
	// 		ID:         dbAlert.ID,
	// 		Type:       dbAlert.Type,
	// 		Severity:   dbAlert.Severity,
	// 		Title:      dbAlert.Title,
	// 		Message:    dbAlert.Message,
	// 		Source:     dbAlert.Source,
	// 		CreatedAt:  dbAlert.CreatedAt.Time,
	// 		UpdatedAt:  dbAlert.UpdatedAt.Time,
	// 		IsActive:   dbAlert.IsActive,
	// 		IsResolved: dbAlert.IsResolved,
	// 	}

	// 	if dbAlert.ResolvedAt.Valid {
	// 		alerts[i].ResolvedAt = &dbAlert.ResolvedAt.Time
	// 	}
	// }

	// return alerts, nil
}

// GetAlertsBySeverity retrieves alerts by severity
func (r *PostgresAlertRepository) GetAlertsBySeverity(ctx context.Context, severity string) ([]interfaces.Alert, error) {
	dbAlerts, err := r.store.GetAlertsBySeverity(ctx, severity)
	if err != nil {
		return nil, err
	}

	alerts := make([]interfaces.Alert, len(dbAlerts))
	for i, dbAlert := range dbAlerts {
		alerts[i] = interfaces.Alert{
			ID:         dbAlert.ID,
			Type:       dbAlert.Type,
			Severity:   dbAlert.Severity,
			Title:      dbAlert.Title,
			Message:    dbAlert.Message,
			Source:     dbAlert.Source,
			CreatedAt:  dbAlert.CreatedAt.Time,
			UpdatedAt:  dbAlert.UpdatedAt.Time,
			IsActive:   dbAlert.IsActive.Bool,
			IsResolved: dbAlert.IsResolved.Bool,
		}

		if dbAlert.ResolvedAt.Valid {
			alerts[i].ResolvedAt = &dbAlert.ResolvedAt.Time
		}
	}

	return alerts, nil
}

// MarkAlertResolved marks an alert as resolved
func (r *PostgresAlertRepository) MarkAlertResolved(ctx context.Context, alertID uuid.UUID) error {
	return r.store.MarkAlertResolved(ctx, db.MarkAlertResolvedParams{
		ID:         alertID,
		ResolvedAt: pgtype.Timestamp{Time: time.Now(), Valid: true},
	})
}

// PostgresNotificationRepository implements the NotificationRepository interface using PostgreSQL
type PostgresNotificationRepository struct {
	db    *postgres.DB
	store *db.Store
}

// NewPostgresNotificationRepository creates a new PostgreSQL notification repository
func NewPostgresNotificationRepository(db *postgres.DB, store *db.Store) interfaces.NotificationRepository {
	return &PostgresNotificationRepository{
		db:    db,
		store: store,
	}
}

// GetNotificationSettings returns notification settings
func (r *PostgresNotificationRepository) GetNotificationSettings(ctx context.Context) (*interfaces.NotificationSettings, error) {
	// For now, return default settings - implement database storage later
	return &interfaces.NotificationSettings{
		EmailEnabled:    true,
		EmailRecipients: []string{"admin@example.com"},
		SlackEnabled:    false,
		SMSEnabled:      false,
		Thresholds: interfaces.NotificationThresholds{
			FailedLoginRate:     10.0,
			ErrorRate:           5.0,
			ResponseTime:        1000,
			DatabaseConnections: 80,
			MemoryUsage:         85.0,
			CPUUsage:            80.0,
		},
	}, nil
}

// UpdateNotificationSettings updates notification settings
func (r *PostgresNotificationRepository) UpdateNotificationSettings(ctx context.Context, req *interfaces.UpdateNotificationSettingsRequest) error {
	// TODO: Implement database storage for notification settings
	return nil
}

// CreateNotificationSettings creates notification settings
func (r *PostgresNotificationRepository) CreateNotificationSettings(ctx context.Context, settings *interfaces.NotificationSettings) error {
	// TODO: Implement database storage for notification settings
	return nil
}

// StubAuditService is a stub implementation of AuditService for admin service
type StubAuditService struct{}

// NewStubAuditService creates a new stub audit service
func NewStubAuditService() interfaces.AuditService {
	return &StubAuditService{}
}

// LogEvent logs an audit event (stub implementation)
func (s *StubAuditService) LogEvent(ctx context.Context, event interfaces.AuditEvent) error {
	return nil
}

// GetUserAuditLogs retrieves audit logs for a specific user (stub implementation)
func (s *StubAuditService) GetUserAuditLogs(ctx context.Context, userID uuid.UUID, req interfaces.GetAuditLogsRequest) (*interfaces.GetAuditLogsResponse, error) {
	return &interfaces.GetAuditLogsResponse{
		AuditLogs:  []*interfaces.AuditLog{},
		TotalCount: 0,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogsByAction retrieves audit logs filtered by action (stub implementation)
func (s *StubAuditService) GetAuditLogsByAction(ctx context.Context, action string, req interfaces.GetAuditLogsRequest) (*interfaces.GetAuditLogsResponse, error) {
	return &interfaces.GetAuditLogsResponse{
		AuditLogs:  []*interfaces.AuditLog{},
		TotalCount: 0,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogsByResource retrieves audit logs for a specific resource (stub implementation)
func (s *StubAuditService) GetAuditLogsByResource(ctx context.Context, resourceType, resourceID string, req interfaces.GetAuditLogsRequest) (*interfaces.GetAuditLogsResponse, error) {
	return &interfaces.GetAuditLogsResponse{
		AuditLogs:  []*interfaces.AuditLog{},
		TotalCount: 0,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogsByTimeRange retrieves audit logs within a time range (stub implementation)
func (s *StubAuditService) GetAuditLogsByTimeRange(ctx context.Context, startTime, endTime time.Time, req interfaces.GetAuditLogsRequest) (*interfaces.GetAuditLogsResponse, error) {
	return &interfaces.GetAuditLogsResponse{
		AuditLogs:  []*interfaces.AuditLog{},
		TotalCount: 0,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetRecentAuditLogs retrieves the most recent audit logs (stub implementation)
func (s *StubAuditService) GetRecentAuditLogs(ctx context.Context, req interfaces.GetAuditLogsRequest) (*interfaces.GetAuditLogsResponse, error) {
	return &interfaces.GetAuditLogsResponse{
		AuditLogs:  []*interfaces.AuditLog{},
		TotalCount: 0,
		Limit:      req.Limit,
		Offset:     req.Offset,
	}, nil
}

// GetAuditLogByID retrieves a specific audit log by ID (stub implementation)
func (s *StubAuditService) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*interfaces.AuditLog, error) {
	return nil, nil
}

// CountAuditLogs returns the total count of audit logs (stub implementation)
func (s *StubAuditService) CountAuditLogs(ctx context.Context) (int64, error) {
	return 0, nil
}

// CountUserAuditLogs returns the count of audit logs for a specific user (stub implementation)
func (s *StubAuditService) CountUserAuditLogs(ctx context.Context, userID uuid.UUID) (int64, error) {
	return 0, nil
}

// CountAuditLogsByAction returns the count of audit logs for a specific action (stub implementation)
func (s *StubAuditService) CountAuditLogsByAction(ctx context.Context, action string) (int64, error) {
	return 0, nil
}

// CleanupOldLogs removes audit logs older than the specified time (stub implementation)
func (s *StubAuditService) CleanupOldLogs(ctx context.Context, olderThan time.Time) error {
	return nil
}
