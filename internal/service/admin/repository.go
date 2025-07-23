package admin

import (
	"context"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// SessionRepository defines the interface for session data access
type SessionRepository interface {
	// GetAllSessions retrieves all user sessions with pagination and filtering
	GetAllSessions(ctx context.Context, req *interfaces.GetSessionsRequest) ([]interfaces.UserSession, int64, error)

	// DeleteSession deletes a specific session
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error

	// GetSessionByID retrieves a session by ID
	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*UserSession, error)

	// GetUserSessions retrieves sessions for a specific user
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]UserSession, error)

	// DeleteUserSessions deletes all sessions for a user
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error

	// GetActiveSessionsCount returns the count of active sessions
	GetActiveSessionsCount(ctx context.Context) (int64, error)

	// CleanupExpiredSessions removes expired sessions
	CleanupExpiredSessions(ctx context.Context) error
}

// AlertRepository defines the interface for alert data access
type AlertRepository interface {
	// CreateAlert creates a new alert
	CreateAlert(ctx context.Context, alert *interfaces.Alert) error

	// GetAlertByID retrieves an alert by ID
	GetAlertByID(ctx context.Context, alertID uuid.UUID) (*interfaces.Alert, error)

	// GetActiveAlerts retrieves all active alerts
	GetActiveAlerts(ctx context.Context) ([]interfaces.Alert, error)

	// GetAlerts retrieves alerts with pagination and filtering
	GetAlerts(ctx context.Context, req *GetAlertsRequest) ([]Alert, int64, error)

	// UpdateAlert updates an existing alert
	UpdateAlert(ctx context.Context, alert *interfaces.Alert) error

	// DeleteAlert deletes an alert
	DeleteAlert(ctx context.Context, alertID uuid.UUID) error

	// GetAlertsByType retrieves alerts by type
	GetAlertsByType(ctx context.Context, alertType string) ([]Alert, error)

	// GetAlertsBySeverity retrieves alerts by severity
	GetAlertsBySeverity(ctx context.Context, severity string) ([]Alert, error)

	// MarkAlertResolved marks an alert as resolved
	MarkAlertResolved(ctx context.Context, alertID uuid.UUID) error
}

// NotificationRepository defines the interface for notification settings data access
type NotificationRepository interface {
	// GetNotificationSettings retrieves notification settings
	GetNotificationSettings(ctx context.Context) (*interfaces.NotificationSettings, error)

	// UpdateNotificationSettings updates notification settings
	UpdateNotificationSettings(ctx context.Context, req *interfaces.UpdateNotificationSettingsRequest) error

	// CreateNotificationSettings creates initial notification settings
	CreateNotificationSettings(ctx context.Context, settings *NotificationSettings) error
}

// GetAlertsRequest represents a request to get alerts with filtering
type GetAlertsRequest struct {
	Page      int    `json:"page" validate:"omitempty,gte=1"`
	Limit     int    `json:"limit" validate:"omitempty,gte=1,lte=100"`
	Type      string `json:"type,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Source    string `json:"source,omitempty"`
	IsActive  *bool  `json:"is_active,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty,oneof=asc desc"`
}
