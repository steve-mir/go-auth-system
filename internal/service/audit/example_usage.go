package audit

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// ExampleUsage demonstrates how to use the audit service
func ExampleUsage() {
	// Create logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create repository (assuming you have a *db.Queries instance)
	var queries *db.Queries // This would be initialized with your database connection
	repo := NewPostgresRepository(queries)

	// Create audit service
	auditService := NewService(repo, logger)

	ctx := context.Background()

	// Example 1: Log a user login event
	userID := uuid.New()
	ipAddr := netip.MustParseAddr("192.168.1.100")

	loginEvent := interfaces.AuditEvent{
		UserID:       userID,
		Action:       ActionUserLogin,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    &ipAddr,
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Metadata: map[string]interface{}{
			"login_method":   "password",
			"success":        true,
			"session_id":     uuid.New().String(),
			"login_duration": "2.3s",
			"previous_login": time.Now().Add(-24 * time.Hour),
		},
	}

	if err := auditService.LogEvent(ctx, loginEvent); err != nil {
		logger.Error("Failed to log login event", "error", err)
	}

	// Example 2: Log a failed login attempt
	failedLoginEvent := interfaces.AuditEvent{
		UserID:       userID,
		Action:       ActionUserLoginFailed,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    &ipAddr,
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Metadata: map[string]interface{}{
			"failure_reason":    "invalid_password",
			"attempt_count":     3,
			"account_locked":    false,
			"lockout_remaining": 2,
		},
	}

	if err := auditService.LogEvent(ctx, failedLoginEvent); err != nil {
		logger.Error("Failed to log failed login event", "error", err)
	}

	// Example 3: Log a role assignment
	adminUserID := uuid.New()
	roleID := uuid.New()

	roleAssignEvent := interfaces.AuditEvent{
		UserID:       adminUserID, // The admin who performed the action
		Action:       ActionRoleAssign,
		ResourceType: ResourceTypeRole,
		ResourceID:   roleID.String(),
		IPAddress:    &ipAddr,
		UserAgent:    "Admin Dashboard v1.0",
		Metadata: map[string]interface{}{
			"target_user_id": userID.String(),
			"role_name":      "moderator",
			"permissions":    []string{"read_posts", "moderate_comments", "ban_users"},
			"assigned_by":    adminUserID.String(),
			"effective_date": time.Now().Format(time.RFC3339),
		},
	}

	if err := auditService.LogEvent(ctx, roleAssignEvent); err != nil {
		logger.Error("Failed to log role assignment event", "error", err)
	}

	// Example 4: Log MFA setup
	mfaSetupEvent := interfaces.AuditEvent{
		UserID:       userID,
		Action:       ActionMFAEnable,
		ResourceType: ResourceTypeMFA,
		ResourceID:   uuid.New().String(),
		IPAddress:    &ipAddr,
		UserAgent:    "Mobile App v2.1.0",
		Metadata: map[string]interface{}{
			"mfa_method":     "totp",
			"backup_codes":   10,
			"device_name":    "iPhone 13 Pro",
			"setup_duration": "45s",
		},
	}

	if err := auditService.LogEvent(ctx, mfaSetupEvent); err != nil {
		logger.Error("Failed to log MFA setup event", "error", err)
	}

	// Example 5: Log suspicious activity
	suspiciousEvent := interfaces.AuditEvent{
		UserID:       userID,
		Action:       ActionSuspiciousActivity,
		ResourceType: ResourceTypeSystem,
		IPAddress:    &ipAddr,
		UserAgent:    "curl/7.68.0",
		Metadata: map[string]interface{}{
			"activity_type":     "unusual_location",
			"risk_score":        85,
			"previous_location": "New York, US",
			"current_location":  "Moscow, RU",
			"time_difference":   "2h",
			"action_taken":      "account_review_required",
		},
	}

	if err := auditService.LogEvent(ctx, suspiciousEvent); err != nil {
		logger.Error("Failed to log suspicious activity event", "error", err)
	}

	// Example 6: Query audit logs
	// Get recent audit logs for a user
	req := interfaces.GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	}

	userLogs, err := auditService.GetUserAuditLogs(ctx, userID, req)
	if err != nil {
		logger.Error("Failed to get user audit logs", "error", err)
	} else {
		logger.Info("Retrieved user audit logs",
			"count", len(userLogs.AuditLogs),
			"total", userLogs.TotalCount)
	}

	// Get all login events
	loginLogs, err := auditService.GetAuditLogsByAction(ctx, ActionUserLogin, req)
	if err != nil {
		logger.Error("Failed to get login audit logs", "error", err)
	} else {
		logger.Info("Retrieved login audit logs",
			"count", len(loginLogs.AuditLogs),
			"total", loginLogs.TotalCount)
	}

	// Get audit logs for a specific time range
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	timeLogs, err := auditService.GetAuditLogsByTimeRange(ctx, startTime, endTime, req)
	if err != nil {
		logger.Error("Failed to get time range audit logs", "error", err)
	} else {
		logger.Info("Retrieved time range audit logs",
			"count", len(timeLogs.AuditLogs),
			"total", timeLogs.TotalCount)
	}

	// Example 7: Cleanup old logs (typically run as a scheduled job)
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)
	if err := auditService.CleanupOldLogs(ctx, thirtyDaysAgo); err != nil {
		logger.Error("Failed to cleanup old audit logs", "error", err)
	} else {
		logger.Info("Successfully cleaned up old audit logs")
	}
}

// ExampleIntegrationWithAuthService shows how to integrate audit logging with authentication service
func ExampleIntegrationWithAuthService(auditService AuditService, userID uuid.UUID, ipAddr netip.Addr, userAgent string) {
	ctx := context.Background()

	// Log successful login
	loginEvent := interfaces.AuditEvent{
		UserID:       userID,
		Action:       ActionUserLogin,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    &ipAddr,
		UserAgent:    userAgent,
		Metadata: map[string]interface{}{
			"login_method": "password",
			"success":      true,
			"timestamp":    time.Now().Unix(),
		},
	}

	auditService.LogEvent(ctx, loginEvent)

	// Log token generation
	tokenEvent := interfaces.AuditEvent{
		UserID:       userID,
		Action:       ActionTokenGenerate,
		ResourceType: ResourceTypeToken,
		IPAddress:    &ipAddr,
		UserAgent:    userAgent,
		Metadata: map[string]interface{}{
			"token_type": "access",
			"expires_in": 3600,
			"scope":      "read write",
		},
	}

	auditService.LogEvent(ctx, tokenEvent)
}

// ExampleBatchAuditLogging shows how to handle multiple audit events efficiently
func ExampleBatchAuditLogging(auditService AuditService) {
	ctx := context.Background()
	userID := uuid.New()
	ipAddr := netip.MustParseAddr("10.0.0.1")

	// Create multiple events that might happen during a user session
	events := []interfaces.AuditEvent{
		{
			UserID:       userID,
			Action:       ActionUserLogin,
			ResourceType: ResourceTypeUser,
			ResourceID:   userID.String(),
			IPAddress:    &ipAddr,
			UserAgent:    "Web Browser",
			Metadata:     map[string]interface{}{"method": "password"},
		},
		{
			UserID:       userID,
			Action:       ActionUserProfileUpdate,
			ResourceType: ResourceTypeUser,
			ResourceID:   userID.String(),
			IPAddress:    &ipAddr,
			UserAgent:    "Web Browser",
			Metadata:     map[string]interface{}{"fields": []string{"email", "phone"}},
		},
		{
			UserID:       userID,
			Action:       ActionUserLogout,
			ResourceType: ResourceTypeUser,
			ResourceID:   userID.String(),
			IPAddress:    &ipAddr,
			UserAgent:    "Web Browser",
			Metadata:     map[string]interface{}{"session_duration": "1h 23m"},
		},
	}

	// Log each event (in a real application, you might want to implement batch logging)
	for _, event := range events {
		if err := auditService.LogEvent(ctx, event); err != nil {
			// Handle error appropriately - maybe log to a separate error log
			// but don't fail the main operation
			continue
		}
	}
}
