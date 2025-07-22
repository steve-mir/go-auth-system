package audit

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents an event to be logged in the audit trail
type AuditEvent struct {
	UserID       uuid.UUID              `json:"user_id"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	IPAddress    *netip.Addr            `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID              `json:"id"`
	UserID       uuid.UUID              `json:"user_id"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	IPAddress    *netip.Addr            `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
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

// GetAuditLogsRequest represents a request for retrieving audit logs with pagination
type GetAuditLogsRequest struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// GetAuditLogsResponse represents a response containing audit logs with pagination info
type GetAuditLogsResponse struct {
	AuditLogs  []*AuditLog `json:"audit_logs"`
	TotalCount int64       `json:"total_count"`
	Limit      int32       `json:"limit"`
	Offset     int32       `json:"offset"`
}

// AuditAction constants for common audit actions
const (
	ActionUserRegister       = "user.register"
	ActionUserLogin          = "user.login"
	ActionUserLoginFailed    = "user.login.failed"
	ActionUserLogout         = "user.logout"
	ActionUserProfileUpdate  = "user.profile.update"
	ActionUserPasswordChange = "user.password.change"
	ActionUserDelete         = "user.delete"
	ActionUserLock           = "user.lock"
	ActionUserUnlock         = "user.unlock"
	ActionUserEmailVerify    = "user.email.verify"
	ActionUserPhoneVerify    = "user.phone.verify"

	ActionTokenGenerate       = "token.generate"
	ActionTokenRefresh        = "token.refresh"
	ActionTokenRevoke         = "token.revoke"
	ActionTokenValidate       = "token.validate"
	ActionTokenValidateFailed = "token.validate.failed"

	ActionRoleCreate   = "role.create"
	ActionRoleUpdate   = "role.update"
	ActionRoleDelete   = "role.delete"
	ActionRoleAssign   = "role.assign"
	ActionRoleUnassign = "role.unassign"

	ActionMFAEnable       = "mfa.enable"
	ActionMFADisable      = "mfa.disable"
	ActionMFAVerify       = "mfa.verify"
	ActionMFAVerifyFailed = "mfa.verify.failed"

	ActionSessionCreate  = "session.create"
	ActionSessionDestroy = "session.destroy"
	ActionSessionExpire  = "session.expire"

	ActionRateLimitExceeded  = "rate_limit.exceeded"
	ActionSuspiciousActivity = "security.suspicious_activity"
	ActionAccountLockout     = "security.account_lockout"

	ActionAdminUserCreate   = "admin.user.create"
	ActionAdminUserUpdate   = "admin.user.update"
	ActionAdminUserDelete   = "admin.user.delete"
	ActionAdminConfigUpdate = "admin.config.update"
	ActionAdminSystemAccess = "admin.system.access"
)

// ResourceType constants for common resource types
const (
	ResourceTypeUser    = "user"
	ResourceTypeRole    = "role"
	ResourceTypeSession = "session"
	ResourceTypeToken   = "token"
	ResourceTypeMFA     = "mfa"
	ResourceTypeConfig  = "config"
	ResourceTypeSystem  = "system"
)

// ToJSON converts metadata map to JSON bytes
func (e *AuditEvent) ToJSON() (json.RawMessage, error) {
	if e.Metadata == nil {
		return json.RawMessage("{}"), nil
	}
	return json.Marshal(e.Metadata)
}

// FromJSON converts JSON bytes to metadata map
func (a *AuditLog) FromJSON(data json.RawMessage) error {
	if len(data) == 0 || string(data) == "{}" {
		a.Metadata = make(map[string]interface{})
		return nil
	}
	return json.Unmarshal(data, &a.Metadata)
}
