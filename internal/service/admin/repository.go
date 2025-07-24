package admin

// // SessionRepository defines the interface for session data access
// type SessionRepository interface {
// 	GetAllSessions(ctx context.Context, req *interfaces.GetSessionsRequest) ([]interfaces.UserSession, int64, error)
// 	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
// 	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*interfaces.UserSession, error)
// 	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]interfaces.UserSession, error)
// 	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
// 	GetActiveSessionsCount(ctx context.Context) (int64, error)
// 	CleanupExpiredSessions(ctx context.Context) error
// }

// // AlertRepository defines the interface for alert data access
// type AlertRepository interface {
// 	CreateAlert(ctx context.Context, alert *interfaces.Alert) error
// 	GetAlertByID(ctx context.Context, alertID uuid.UUID) (*interfaces.Alert, error)
// 	GetActiveAlerts(ctx context.Context) ([]interfaces.Alert, error)
// 	GetAlerts(ctx context.Context, req *GetAlertsRequest) ([]interfaces.Alert, int64, error)
// 	UpdateAlert(ctx context.Context, alert *interfaces.Alert) error
// 	DeleteAlert(ctx context.Context, alertID uuid.UUID) error
// 	GetAlertsByType(ctx context.Context, alertType string) ([]interfaces.Alert, error)
// 	GetAlertsBySeverity(ctx context.Context, severity string) ([]interfaces.Alert, error)
// 	MarkAlertResolved(ctx context.Context, alertID uuid.UUID) error
// }

// // NotificationRepository defines the interface for notification settings data access
// type NotificationRepository interface {
// 	GetNotificationSettings(ctx context.Context) (*interfaces.NotificationSettings, error)
// 	UpdateNotificationSettings(ctx context.Context, req *interfaces.UpdateNotificationSettingsRequest) error
// 	CreateNotificationSettings(ctx context.Context, settings *interfaces.NotificationSettings) error
// }

// // GetAlertsRequest represents a request to get alerts with filtering
// type GetAlertsRequest struct {
// 	Page      int       `json:"page" validate:"omitempty,gte=1"`
// 	Limit     int       `json:"limit" validate:"omitempty,gte=1,lte=100"`
// 	Type      string    `json:"type,omitempty"`
// 	Severity  string    `json:"severity,omitempty"`
// 	IsActive  *bool     `json:"is_active,omitempty"`
// 	StartTime time.Time `json:"start_time,omitempty"`
// 	EndTime   time.Time `json:"end_time,omitempty"`
// 	SortBy    string    `json:"sort_by,omitempty"`
// 	SortOrder string    `json:"sort_order,omitempty"`
// }
