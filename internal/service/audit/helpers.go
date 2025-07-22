package audit

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Helper functions to make audit logging easier to use

// LogUserLogin logs a successful user login event
func LogUserLogin(ctx context.Context, service AuditService, userID uuid.UUID, ipAddr *netip.Addr, userAgent string, metadata map[string]interface{}) error {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["success"] = true
	metadata["timestamp"] = time.Now().Unix()

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionUserLogin,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogUserLoginFailed logs a failed user login attempt
func LogUserLoginFailed(ctx context.Context, service AuditService, userID uuid.UUID, ipAddr *netip.Addr, userAgent string, reason string, metadata map[string]interface{}) error {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["success"] = false
	metadata["failure_reason"] = reason
	metadata["timestamp"] = time.Now().Unix()

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionUserLoginFailed,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogUserLogout logs a user logout event
func LogUserLogout(ctx context.Context, service AuditService, userID uuid.UUID, ipAddr *netip.Addr, userAgent string, sessionDuration time.Duration) error {
	metadata := map[string]interface{}{
		"session_duration": sessionDuration.String(),
		"timestamp":        time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionUserLogout,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogUserRegistration logs a user registration event
func LogUserRegistration(ctx context.Context, service AuditService, userID uuid.UUID, ipAddr *netip.Addr, userAgent string, email string) error {
	metadata := map[string]interface{}{
		"email":     email,
		"timestamp": time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionUserRegister,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogPasswordChange logs a password change event
func LogPasswordChange(ctx context.Context, service AuditService, userID uuid.UUID, ipAddr *netip.Addr, userAgent string, method string) error {
	metadata := map[string]interface{}{
		"change_method": method, // "self_service", "admin_reset", "forced_reset"
		"timestamp":     time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionUserPasswordChange,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogRoleAssignment logs a role assignment event
func LogRoleAssignment(ctx context.Context, service AuditService, adminUserID, targetUserID, roleID uuid.UUID, roleName string, ipAddr *netip.Addr, userAgent string) error {
	metadata := map[string]interface{}{
		"target_user_id": targetUserID.String(),
		"role_name":      roleName,
		"assigned_by":    adminUserID.String(),
		"timestamp":      time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       adminUserID,
		Action:       ActionRoleAssign,
		ResourceType: ResourceTypeRole,
		ResourceID:   roleID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogMFASetup logs an MFA setup event
func LogMFASetup(ctx context.Context, service AuditService, userID uuid.UUID, mfaMethod string, ipAddr *netip.Addr, userAgent string) error {
	metadata := map[string]interface{}{
		"mfa_method": mfaMethod, // "totp", "sms", "email", "webauthn"
		"timestamp":  time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionMFAEnable,
		ResourceType: ResourceTypeMFA,
		ResourceID:   uuid.New().String(), // Generate a new ID for the MFA setup
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogSuspiciousActivity logs a suspicious activity event
func LogSuspiciousActivity(ctx context.Context, service AuditService, userID uuid.UUID, activityType string, riskScore int, ipAddr *netip.Addr, userAgent string, details map[string]interface{}) error {
	metadata := map[string]interface{}{
		"activity_type": activityType,
		"risk_score":    riskScore,
		"timestamp":     time.Now().Unix(),
	}

	// Merge additional details
	for k, v := range details {
		metadata[k] = v
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionSuspiciousActivity,
		ResourceType: ResourceTypeSystem,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogTokenGeneration logs a token generation event
func LogTokenGeneration(ctx context.Context, service AuditService, userID uuid.UUID, tokenType string, expiresIn int64, ipAddr *netip.Addr, userAgent string) error {
	metadata := map[string]interface{}{
		"token_type": tokenType, // "access", "refresh"
		"expires_in": expiresIn,
		"timestamp":  time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionTokenGenerate,
		ResourceType: ResourceTypeToken,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogAdminAction logs an administrative action
func LogAdminAction(ctx context.Context, service AuditService, adminUserID uuid.UUID, action, resourceType, resourceID string, ipAddr *netip.Addr, userAgent string, details map[string]interface{}) error {
	metadata := map[string]interface{}{
		"admin_user_id": adminUserID.String(),
		"timestamp":     time.Now().Unix(),
	}

	// Merge additional details
	for k, v := range details {
		metadata[k] = v
	}

	event := AuditEvent{
		UserID:       adminUserID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogRateLimitExceeded logs a rate limit exceeded event
func LogRateLimitExceeded(ctx context.Context, service AuditService, userID uuid.UUID, limitType string, currentCount, maxCount int, ipAddr *netip.Addr, userAgent string) error {
	metadata := map[string]interface{}{
		"limit_type":    limitType, // "login_attempts", "api_requests", "password_resets"
		"current_count": currentCount,
		"max_count":     maxCount,
		"timestamp":     time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionRateLimitExceeded,
		ResourceType: ResourceTypeSystem,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogAccountLockout logs an account lockout event
func LogAccountLockout(ctx context.Context, service AuditService, userID uuid.UUID, reason string, duration time.Duration, ipAddr *netip.Addr, userAgent string) error {
	metadata := map[string]interface{}{
		"lockout_reason":   reason, // "failed_attempts", "suspicious_activity", "admin_action"
		"lockout_duration": duration.String(),
		"timestamp":        time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionAccountLockout,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogSessionCreation logs a session creation event
func LogSessionCreation(ctx context.Context, service AuditService, userID, sessionID uuid.UUID, ipAddr *netip.Addr, userAgent string, expiresAt time.Time) error {
	metadata := map[string]interface{}{
		"session_id": sessionID.String(),
		"expires_at": expiresAt.Unix(),
		"timestamp":  time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionSessionCreate,
		ResourceType: ResourceTypeSession,
		ResourceID:   sessionID.String(),
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}

// LogConfigurationChange logs a configuration change event
func LogConfigurationChange(ctx context.Context, service AuditService, adminUserID uuid.UUID, configKey string, oldValue, newValue interface{}, ipAddr *netip.Addr, userAgent string) error {
	metadata := map[string]interface{}{
		"config_key": configKey,
		"old_value":  oldValue,
		"new_value":  newValue,
		"changed_by": adminUserID.String(),
		"timestamp":  time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:       adminUserID,
		Action:       ActionAdminConfigUpdate,
		ResourceType: ResourceTypeConfig,
		ResourceID:   configKey,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	return service.LogEvent(ctx, event)
}
