package interfaces

import (
	"context"
	"net/netip"
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

// UserService interface - extracted from user package
type UserService interface {
	GetProfile(ctx context.Context, userID string) (*UserProfile, error)
	UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserProfile, error)
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error)
	ChangePassword(ctx context.Context, userID string, req *ChangePasswordRequest) error
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// RoleService interface - extracted from role package
type RoleService interface {
	CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error)
	GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, req UpdateRoleRequest) (*Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error
	ListRoles(ctx context.Context, req ListRolesRequest) (*ListRolesResponse, error)
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*UserInfo, error)
	ValidateAccess(ctx context.Context, req AccessRequest) (*AccessResponse, error)
	ValidatePermission(ctx context.Context, userID uuid.UUID, permission Permission) (bool, error)

	ValidatePermissions(ctx context.Context, userID uuid.UUID, permissions []Permission) (map[string]bool, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error)
	// Advanced permission management
	GetEffectivePermissions(ctx context.Context, userID uuid.UUID) ([]Permission, error)
	CheckResourceAccess(ctx context.Context, userID uuid.UUID, resource string, actions []string) (map[string]bool, error)
	ValidateRoleHierarchy(ctx context.Context, userID uuid.UUID, requiredRole string) (bool, error)
}

// SessionRepository defines the interface for session data access
type SessionRepository interface {
	GetAllSessions(ctx context.Context, req *GetSessionsRequest) ([]UserSession, int64, error)
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*UserSession, error)
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]UserSession, error)
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	GetActiveSessionsCount(ctx context.Context) (int64, error)
	CleanupExpiredSessions(ctx context.Context) error
}

// GetAlertsRequest represents a request to get alerts with filtering
type GetAlertsRequest struct {
	Page      int       `json:"page" validate:"omitempty,gte=1"`
	Limit     int       `json:"limit" validate:"omitempty,gte=1,lte=100"`
	Type      string    `json:"type,omitempty"`
	Source    string    `json:"source,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	IsActive  *bool     `json:"is_active,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	SortBy    string    `json:"sort_by,omitempty"`
	SortOrder string    `json:"sort_order,omitempty"`
}

// AlertRepository defines the interface for alert data access
type AlertRepository interface {
	CreateAlert(ctx context.Context, alert *Alert) error
	GetAlertByID(ctx context.Context, alertID uuid.UUID) (*Alert, error)
	GetActiveAlerts(ctx context.Context) ([]Alert, error)
	GetAlerts(ctx context.Context, req *GetAlertsRequest) ([]Alert, int64, error)
	UpdateAlert(ctx context.Context, alert *Alert) error
	DeleteAlert(ctx context.Context, alertID uuid.UUID) error
	GetAlertsByType(ctx context.Context, alertType string) ([]Alert, error)
	GetAlertsBySeverity(ctx context.Context, severity string) ([]Alert, error)
	MarkAlertResolved(ctx context.Context, alertID uuid.UUID) error
}

// NotificationRepository defines the interface for notification settings data access
type NotificationRepository interface {
	GetNotificationSettings(ctx context.Context) (*NotificationSettings, error)
	UpdateNotificationSettings(ctx context.Context, req *UpdateNotificationSettingsRequest) error
	CreateNotificationSettings(ctx context.Context, settings *NotificationSettings) error
}

// EmailService defines the interface for email operations
type EmailService interface {
	// Send a single email
	SendEmail(ctx context.Context, req *SendEmailRequest) error

	// Send bulk emails
	SendBulkEmails(ctx context.Context, req *BulkEmailRequest) error

	// Pre-made template methods
	SendWelcomeEmail(ctx context.Context, to, name string) error
	SendVerificationEmail(ctx context.Context, to, name, token string) error
	SendPasswordResetEmail(ctx context.Context, to, name, token string) error
	SendLoginNotificationEmail(ctx context.Context, to, name, location, device string) error
	SendMFACodeEmail(ctx context.Context, to, name, code string) error
	SendAccountLockedEmail(ctx context.Context, to, name string) error
	SendPasswordChangedEmail(ctx context.Context, to, name string) error

	// Template management
	CreateTemplate(ctx context.Context, template *EmailTemplate) error
	UpdateTemplate(ctx context.Context, id string, template *EmailTemplate) error
	GetTemplate(ctx context.Context, id string) (*EmailTemplate, error)
	DeleteTemplate(ctx context.Context, id string) error
	ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*EmailTemplate, error)

	// Email tracking and analytics
	GetEmailStatus(ctx context.Context, emailID string) (*EmailStatus, error)
	GetEmailAnalytics(ctx context.Context, filter *AnalyticsFilter) (*EmailAnalytics, error)

	// Health check
	HealthCheck(ctx context.Context) error
}

// AdminService defines the interface for admin dashboard operations
type AdminService interface {
	// System information and health
	GetSystemInfo(ctx context.Context) (*SystemInfo, error)
	GetSystemHealth(ctx context.Context) (*SystemHealth, error)
	GetSystemMetrics(ctx context.Context) (*SystemMetrics, error)

	// User management
	GetUserStats(ctx context.Context) (*UserStats, error)
	BulkUserActions(ctx context.Context, req *BulkUserActionRequest) (*BulkActionResult, error)
	GetAllUserSessions(ctx context.Context, req *GetSessionsRequest) (*GetSessionsResponse, error)
	DeleteUserSession(ctx context.Context, sessionID uuid.UUID) error

	// Role management
	GetRoleStats(ctx context.Context) (*RoleStats, error)
	BulkRoleAssign(ctx context.Context, req *BulkRoleAssignRequest) (*BulkActionResult, error)

	// Audit and logging
	GetAuditLogs(ctx context.Context, req *GetAuditLogsRequest) (*GetAuditLogsResponse, error)
	GetAuditEvents(ctx context.Context, req *GetAuditEventsRequest) (*GetAuditEventsResponse, error)

	// Configuration management
	GetConfiguration(ctx context.Context) (*ConfigurationResponse, error)
	UpdateConfiguration(ctx context.Context, req *UpdateConfigurationRequest) error
	ReloadConfiguration(ctx context.Context) error

	// Alerts and notifications
	GetActiveAlerts(ctx context.Context) (*AlertsResponse, error)
	CreateAlert(ctx context.Context, req *CreateAlertRequest) (*Alert, error)
	UpdateAlert(ctx context.Context, alertID uuid.UUID, req *UpdateAlertRequest) (*Alert, error)
	DeleteAlert(ctx context.Context, alertID uuid.UUID) error
	GetNotificationSettings(ctx context.Context) (*NotificationSettings, error)
	UpdateNotificationSettings(ctx context.Context, req *UpdateNotificationSettingsRequest) error
}

// Data structures

// SystemInfo represents system information
type SystemInfo struct {
	Service   string                 `json:"service"`
	Version   string                 `json:"version"`
	Build     BuildInfo              `json:"build"`
	Runtime   RuntimeInfo            `json:"runtime"`
	Features  map[string]interface{} `json:"features"`
	Timestamp time.Time              `json:"timestamp"`
}

// BuildInfo represents build information
type BuildInfo struct {
	GoVersion string    `json:"go_version"`
	BuildTime time.Time `json:"build_time"`
	GitCommit string    `json:"git_commit"`
	GitBranch string    `json:"git_branch"`
	BuildUser string    `json:"build_user"`
	BuildHost string    `json:"build_host"`
}

// RuntimeInfo represents runtime information
type RuntimeInfo struct {
	Uptime      time.Duration `json:"uptime"`
	StartTime   time.Time     `json:"start_time"`
	GoRoutines  int           `json:"go_routines"`
	MemoryUsage MemoryInfo    `json:"memory_usage"`
	CPUUsage    float64       `json:"cpu_usage"`
	Environment string        `json:"environment"`
}

// MemoryInfo represents memory usage information
type MemoryInfo struct {
	Allocated    uint64 `json:"allocated"`
	TotalAlloc   uint64 `json:"total_alloc"`
	SystemMemory uint64 `json:"system_memory"`
	NumGC        uint32 `json:"num_gc"`
	HeapObjects  uint64 `json:"heap_objects"`
}

// SystemHealth represents system health status
type SystemHealth struct {
	Status     string                     `json:"status"`
	Components map[string]ComponentHealth `json:"components"`
	Timestamp  time.Time                  `json:"timestamp"`
}

// ComponentHealth represents health status of a system component
type ComponentHealth struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

// SystemMetrics represents system metrics
type SystemMetrics struct {
	Requests       RequestMetrics  `json:"requests"`
	Authentication AuthMetrics     `json:"authentication"`
	Users          UserMetrics     `json:"users"`
	Tokens         TokenMetrics    `json:"tokens"`
	Database       DatabaseMetrics `json:"database"`
	Cache          CacheMetrics    `json:"cache"`
	Security       SecurityMetrics `json:"security"`
	Timestamp      time.Time       `json:"timestamp"`
}

// RequestMetrics represents HTTP request metrics
type RequestMetrics struct {
	Total       int64   `json:"total"`
	SuccessRate float64 `json:"success_rate"`
	AvgLatency  string  `json:"avg_latency"`
	P95Latency  string  `json:"p95_latency"`
	P99Latency  string  `json:"p99_latency"`
	ErrorRate   float64 `json:"error_rate"`
}

// AuthMetrics represents authentication metrics
type AuthMetrics struct {
	TotalLogins    int64   `json:"total_logins"`
	FailedLogins   int64   `json:"failed_logins"`
	SuccessRate    float64 `json:"success_rate"`
	ActiveSessions int64   `json:"active_sessions"`
	MFAUsage       float64 `json:"mfa_usage"`
}

// UserMetrics represents user metrics
type UserMetrics struct {
	TotalUsers     int64 `json:"total_users"`
	ActiveUsers    int64 `json:"active_users"`
	VerifiedUsers  int64 `json:"verified_users"`
	LockedAccounts int64 `json:"locked_accounts"`
	NewUsers24h    int64 `json:"new_users_24h"`
	NewUsers7d     int64 `json:"new_users_7d"`
}

// TokenMetrics represents token metrics
type TokenMetrics struct {
	IssuedTokens      int64   `json:"issued_tokens"`
	ActiveTokens      int64   `json:"active_tokens"`
	ExpiredTokens     int64   `json:"expired_tokens"`
	BlacklistedTokens int64   `json:"blacklisted_tokens"`
	RefreshRate       float64 `json:"refresh_rate"`
}

// DatabaseMetrics represents database metrics
type DatabaseMetrics struct {
	ActiveConnections int     `json:"active_connections"`
	IdleConnections   int     `json:"idle_connections"`
	MaxConnections    int     `json:"max_connections"`
	AvgQueryTime      string  `json:"avg_query_time"`
	SlowQueries       int64   `json:"slow_queries"`
	ErrorRate         float64 `json:"error_rate"`
}

// CacheMetrics represents cache metrics
type CacheMetrics struct {
	HitRate       float64 `json:"hit_rate"`
	MissRate      float64 `json:"miss_rate"`
	MemoryUsage   string  `json:"memory_usage"`
	KeyCount      int64   `json:"key_count"`
	EvictionCount int64   `json:"eviction_count"`
}

// SecurityMetrics represents security metrics
type SecurityMetrics struct {
	RateLimitHits      int64 `json:"rate_limit_hits"`
	BlockedRequests    int64 `json:"blocked_requests"`
	SuspiciousActivity int64 `json:"suspicious_activity"`
	FailedAuthAttempts int64 `json:"failed_auth_attempts"`
}

// UserStats represents user statistics
type UserStats struct {
	TotalUsers        int64                    `json:"total_users"`
	ActiveUsers       int64                    `json:"active_users"`
	VerifiedUsers     int64                    `json:"verified_users"`
	LockedAccounts    int64                    `json:"locked_accounts"`
	UsersByRole       map[string]int64         `json:"users_by_role"`
	RegistrationTrend []RegistrationTrendPoint `json:"registration_trend"`
	LoginTrend        []LoginTrendPoint        `json:"login_trend"`
}

// RegistrationTrendPoint represents a point in registration trend
type RegistrationTrendPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// LoginTrendPoint represents a point in login trend
type LoginTrendPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// BulkUserActionRequest represents a bulk user action request
type BulkUserActionRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" validate:"required,min=1"`
	Action  string      `json:"action" validate:"required,oneof=lock unlock verify_email verify_phone delete enable_mfa disable_mfa"`
	Reason  string      `json:"reason,omitempty"`
}

// BulkActionResult represents the result of a bulk action
type BulkActionResult struct {
	Action  string         `json:"action"`
	Total   int            `json:"total"`
	Success int            `json:"success"`
	Failed  int            `json:"failed"`
	Errors  []string       `json:"errors,omitempty"`
	Details []ActionDetail `json:"details,omitempty"`
}

// ActionDetail represents details of an individual action
type ActionDetail struct {
	UserID  uuid.UUID `json:"user_id"`
	Success bool      `json:"success"`
	Error   string    `json:"error,omitempty"`
}

// GetSessionsRequest represents a request to get user sessions
type GetSessionsRequest struct {
	Page      int    `json:"page" validate:"omitempty,gte=1"`
	Limit     int    `json:"limit" validate:"omitempty,gte=1,lte=100"`
	UserID    string `json:"user_id,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty,oneof=asc desc"`
}

// GetSessionsResponse represents the response for getting user sessions
type GetSessionsResponse struct {
	Sessions   []UserSession  `json:"sessions"`
	Pagination PaginationInfo `json:"pagination"`
}

// UserSession represents a user session
type UserSession struct {
	SessionID uuid.UUID `json:"session_id"`
	UserID    uuid.UUID `json:"user_id"`
	UserEmail string    `json:"user_email"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenType string    `json:"token_type"`
	IsActive  bool      `json:"is_active"`
}

// PaginationInfo represents pagination information
type PaginationInfo struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// RoleStats represents role statistics
type RoleStats struct {
	TotalRoles      int64            `json:"total_roles"`
	RoleUsage       map[string]int64 `json:"role_usage"`
	PermissionUsage map[string]int64 `json:"permission_usage"`
}

// BulkRoleAssignRequest represents a bulk role assignment request
type BulkRoleAssignRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" validate:"required,min=1"`
	RoleID  uuid.UUID   `json:"role_id" validate:"required"`
	Action  string      `json:"action" validate:"required,oneof=assign remove"`
	Reason  string      `json:"reason,omitempty"`
}

//	type GetAuditLogsRequest struct {
//		Limit  int32 `json:"limit"`
//		Offset int32 `json:"offset"`
//	}
//
// GetAuditLogsRequest represents a request to get audit logs
type GetAuditLogsRequest struct {
	Page         int32     `json:"page" validate:"omitempty,gte=1"`
	Limit        int32     `json:"limit" validate:"omitempty,gte=1,lte=100"`
	Offset       int32     `json:"offset"`
	UserID       string    `json:"user_id,omitempty"`
	Action       string    `json:"action,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	StartTime    time.Time `json:"start_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
	SortBy       string    `json:"sort_by,omitempty"`
	SortOrder    string    `json:"sort_order,omitempty,oneof=asc desc"`
}

// GetAuditLogsResponse represents the response for getting audit logs
//
//	type GetAuditLogsResponse struct {
//		Logs       []AuditLog     `json:"logs"`
//		Pagination PaginationInfo `json:"pagination"`
//	}
type GetAuditLogsResponse struct {
	AuditLogs  []*AuditLog `json:"audit_logs"`
	TotalCount int64       `json:"total_count"`
	Limit      int32       `json:"limit"`
	Offset     int32       `json:"offset"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID              `json:"id"`
	UserID       uuid.UUID              `json:"user_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	IPAddress    *netip.Addr            `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// GetAuditEventsRequest represents a request to get audit events
type GetAuditEventsRequest struct {
	Page      int    `json:"page" validate:"omitempty,gte=1"`
	Limit     int    `json:"limit" validate:"omitempty,gte=1,lte=100"`
	EventType string `json:"event_type,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty,oneof=asc desc"`
}

// GetAuditEventsResponse represents the response for getting audit events
type GetAuditEventsResponse struct {
	Events     []AuditEvent   `json:"events"`
	Pagination PaginationInfo `json:"pagination"`
}

// CreateAuditLogParams represents parameters for creating an audit log
type CreateAuditLogParams struct {
	UserID       uuid.UUID              `json:"user_id"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	IPAddress    *netip.Addr            `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AuditEvent represents an audit event summary
type AuditEvent struct {
	EventType    string                 `json:"event_type"`
	Count        int64                  `json:"count"`
	LastSeen     time.Time              `json:"last_seen"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	UserID       uuid.UUID              `json:"user_id"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	IPAddress    *netip.Addr            `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
}

// AuditEvent represents an event to be logged in the audit trail
// type AuditEvent struct {
// 	UserID       uuid.UUID              `json:"user_id"`
// 	Action       string                 `json:"action"`
// 	ResourceType string                 `json:"resource_type,omitempty"`
// 	ResourceID   string                 `json:"resource_id,omitempty"`
// 	IPAddress    *netip.Addr            `json:"ip_address,omitempty"`
// 	UserAgent    string                 `json:"user_agent,omitempty"`
// 	Metadata     map[string]interface{} `json:"metadata,omitempty"`
// }

// ConfigurationResponse represents the current configuration
type ConfigurationResponse struct {
	Server   ServerConfig   `json:"server"`
	Security SecurityConfig `json:"security"`
	Features FeaturesConfig `json:"features"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Environment string `json:"environment"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	PasswordHash PasswordHashConfig `json:"password_hash"`
	Token        TokenConfig        `json:"token"`
	RateLimit    RateLimitConfig    `json:"rate_limit"`
}

// PasswordHashConfig represents password hash configuration
type PasswordHashConfig struct {
	Algorithm string `json:"algorithm"`
}

// TokenConfig represents token configuration
type TokenConfig struct {
	Type       string `json:"type"`
	AccessTTL  string `json:"access_ttl"`
	RefreshTTL string `json:"refresh_ttl"`
}

// RateLimitConfig represents rate limit configuration
type RateLimitConfig struct {
	Enabled        bool   `json:"enabled"`
	RequestsPerMin int    `json:"requests_per_minute"`
	BurstSize      int    `json:"burst_size"`
	WindowSize     string `json:"window_size"`
}

// FeaturesConfig represents features configuration
type FeaturesConfig struct {
	MFAEnabled     bool `json:"mfa_enabled"`
	SocialAuth     bool `json:"social_auth"`
	EnterpriseSSO  bool `json:"enterprise_sso"`
	AdminDashboard bool `json:"admin_dashboard"`
	AuditLogging   bool `json:"audit_logging"`
}

// UpdateConfigurationRequest represents a configuration update request
type UpdateConfigurationRequest struct {
	Server   *ServerConfig   `json:"server,omitempty"`
	Security *SecurityConfig `json:"security,omitempty"`
	Features *FeaturesConfig `json:"features,omitempty"`
}

// AlertsResponse represents the response for getting alerts
type AlertsResponse struct {
	Alerts []Alert `json:"alerts"`
	Total  int     `json:"total"`
}

// Alert represents a system alert
type Alert struct {
	ID         uuid.UUID              `json:"id"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	Source     string                 `json:"source"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	ResolvedAt *time.Time             `json:"resolved_at,omitempty"`
	IsActive   bool                   `json:"is_active"`
	IsResolved bool                   `json:"is_resolved"`
}

// CreateAlertRequest represents a request to create an alert
type CreateAlertRequest struct {
	Type     string                 `json:"type" validate:"required"`
	Severity string                 `json:"severity" validate:"required,oneof=low medium high critical"`
	Title    string                 `json:"title" validate:"required,max=200"`
	Message  string                 `json:"message" validate:"required,max=1000"`
	Source   string                 `json:"source" validate:"required"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateAlertRequest represents a request to update an alert
type UpdateAlertRequest struct {
	Severity   *string                `json:"severity,omitempty" validate:"omitempty,oneof=low medium high critical"`
	Title      *string                `json:"title,omitempty" validate:"omitempty,max=200"`
	Message    *string                `json:"message,omitempty" validate:"omitempty,max=1000"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	IsResolved *bool                  `json:"is_resolved,omitempty"`
}

// NotificationSettings represents notification settings
type NotificationSettings struct {
	EmailEnabled    bool                   `json:"email_enabled"`
	EmailRecipients []string               `json:"email_recipients"`
	SlackEnabled    bool                   `json:"slack_enabled"`
	SlackWebhook    string                 `json:"slack_webhook,omitempty"`
	SMSEnabled      bool                   `json:"sms_enabled"`
	SMSRecipients   []string               `json:"sms_recipients"`
	Thresholds      NotificationThresholds `json:"thresholds"`
}

// NotificationThresholds represents notification thresholds
type NotificationThresholds struct {
	FailedLoginRate     float64 `json:"failed_login_rate"`
	ErrorRate           float64 `json:"error_rate"`
	ResponseTime        int     `json:"response_time_ms"`
	DatabaseConnections int     `json:"database_connections"`
	MemoryUsage         float64 `json:"memory_usage_percent"`
	CPUUsage            float64 `json:"cpu_usage_percent"`
}

// UpdateNotificationSettingsRequest represents a request to update notification settings
type UpdateNotificationSettingsRequest struct {
	EmailEnabled    *bool                   `json:"email_enabled,omitempty"`
	EmailRecipients []string                `json:"email_recipients,omitempty"`
	SlackEnabled    *bool                   `json:"slack_enabled,omitempty"`
	SlackWebhook    *string                 `json:"slack_webhook,omitempty"`
	SMSEnabled      *bool                   `json:"sms_enabled,omitempty"`
	SMSRecipients   []string                `json:"sms_recipients,omitempty"`
	Thresholds      *NotificationThresholds `json:"thresholds,omitempty"`
}

// Email service data structures

// SendEmailRequest represents a single email request
type SendEmailRequest struct {
	To          []string           `json:"to"`
	CC          []string           `json:"cc,omitempty"`
	BCC         []string           `json:"bcc,omitempty"`
	From        string             `json:"from,omitempty"`
	FromName    string             `json:"from_name,omitempty"`
	Subject     string             `json:"subject"`
	HTMLBody    string             `json:"html_body,omitempty"`
	TextBody    string             `json:"text_body,omitempty"`
	TemplateID  string             `json:"template_id,omitempty"`
	Variables   map[string]string  `json:"variables,omitempty"`
	Attachments []*EmailAttachment `json:"attachments,omitempty"`
	Priority    EmailPriority      `json:"priority,omitempty"`
	Tags        []string           `json:"tags,omitempty"`
	Metadata    map[string]string  `json:"metadata,omitempty"`
}

// BulkEmailRequest represents a bulk email request
type BulkEmailRequest struct {
	Emails       []*SendEmailRequest `json:"emails"`
	BatchSize    int                 `json:"batch_size,omitempty"`
	DelayBetween time.Duration       `json:"delay_between,omitempty"`
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
	Inline      bool   `json:"inline,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
}

// EmailTemplate represents an email template
type EmailTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Subject     string    `json:"subject"`
	HTMLBody    string    `json:"html_body"`
	TextBody    string    `json:"text_body,omitempty"`
	Variables   []string  `json:"variables,omitempty"`
	Category    string    `json:"category,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
	UpdatedBy   string    `json:"updated_by"`
}

// TemplateFilter represents filters for template queries
type TemplateFilter struct {
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	IsActive *bool    `json:"is_active,omitempty"`
	Search   string   `json:"search,omitempty"`
	Limit    int      `json:"limit,omitempty"`
	Offset   int      `json:"offset,omitempty"`
}

// EmailStatus represents the status of a sent email
type EmailStatus struct {
	ID          string            `json:"id"`
	Status      DeliveryStatus    `json:"status"`
	SentAt      *time.Time        `json:"sent_at,omitempty"`
	DeliveredAt *time.Time        `json:"delivered_at,omitempty"`
	OpenedAt    *time.Time        `json:"opened_at,omitempty"`
	ClickedAt   *time.Time        `json:"clicked_at,omitempty"`
	BouncedAt   *time.Time        `json:"bounced_at,omitempty"`
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// EmailAnalytics represents email analytics data
type EmailAnalytics struct {
	TotalSent      int64   `json:"total_sent"`
	TotalDelivered int64   `json:"total_delivered"`
	TotalOpened    int64   `json:"total_opened"`
	TotalClicked   int64   `json:"total_clicked"`
	TotalBounced   int64   `json:"total_bounced"`
	DeliveryRate   float64 `json:"delivery_rate"`
	OpenRate       float64 `json:"open_rate"`
	ClickRate      float64 `json:"click_rate"`
	BounceRate     float64 `json:"bounce_rate"`
}

// AnalyticsFilter represents filters for analytics queries
type AnalyticsFilter struct {
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	TemplateID string    `json:"template_id,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	Category   string    `json:"category,omitempty"`
}

// EmailPriority represents email priority levels
type EmailPriority string

const (
	PriorityLow    EmailPriority = "low"
	PriorityNormal EmailPriority = "normal"
	PriorityHigh   EmailPriority = "high"
	PriorityUrgent EmailPriority = "urgent"
)

// DeliveryStatus represents email delivery status
type DeliveryStatus string

const (
	StatusPending   DeliveryStatus = "pending"
	StatusSent      DeliveryStatus = "sent"
	StatusDelivered DeliveryStatus = "delivered"
	StatusOpened    DeliveryStatus = "opened"
	StatusClicked   DeliveryStatus = "clicked"
	StatusBounced   DeliveryStatus = "bounced"
	StatusFailed    DeliveryStatus = "failed"
)

// EmailEvent represents an email event
type EmailEvent struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}
