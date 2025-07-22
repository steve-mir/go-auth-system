# Audit Service

The audit service provides comprehensive audit logging functionality for the authentication system. It captures immutable audit trails for all authentication events, security actions, and administrative operations.

## Features

- **Immutable Audit Logging**: All audit events are stored permanently and cannot be modified
- **Structured Logging**: Events are logged with structured metadata for easy querying and analysis
- **Comprehensive Event Coverage**: Supports all authentication, authorization, and administrative events
- **Flexible Querying**: Query audit logs by user, action, resource, time range, and more
- **Pagination Support**: Efficient pagination for large audit log datasets
- **Metadata Support**: Rich metadata capture for detailed forensic analysis
- **Performance Optimized**: Uses SQLC for type-safe, efficient database operations

## Architecture

The audit service follows a layered architecture:

```
┌─────────────────┐
│   Service API   │  ← Public interface (AuditService)
├─────────────────┤
│ Business Logic  │  ← Event validation, structured logging
├─────────────────┤
│   Repository    │  ← Data access abstraction (AuditRepository)
├─────────────────┤
│   Database      │  ← PostgreSQL with SQLC-generated queries
└─────────────────┘
```

## Usage

### Basic Setup

```go
import (
    "github.com/steve-mir/go-auth-system/internal/service/audit"
    "github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// Create repository
queries := db.New(dbPool) // Your database connection
repo := audit.NewPostgresRepository(queries)

// Create service
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
auditService := audit.NewService(repo, logger)
```

### Logging Events

```go
ctx := context.Background()
userID := uuid.New()
ipAddr := netip.MustParseAddr("192.168.1.100")

// Log a user login event
event := audit.AuditEvent{
    UserID:       userID,
    Action:       audit.ActionUserLogin,
    ResourceType: audit.ResourceTypeUser,
    ResourceID:   userID.String(),
    IPAddress:    &ipAddr,
    UserAgent:    "Mozilla/5.0...",
    Metadata: map[string]interface{}{
        "login_method": "password",
        "success":      true,
        "session_id":   sessionID,
    },
}

err := auditService.LogEvent(ctx, event)
```

### Querying Audit Logs

```go
// Get audit logs for a specific user
req := audit.GetAuditLogsRequest{
    Limit:  50,
    Offset: 0,
}

userLogs, err := auditService.GetUserAuditLogs(ctx, userID, req)
if err != nil {
    // handle error
}

// Get all login events
loginLogs, err := auditService.GetAuditLogsByAction(ctx, audit.ActionUserLogin, req)

// Get logs within a time range
startTime := time.Now().Add(-24 * time.Hour)
endTime := time.Now()
timeLogs, err := auditService.GetAuditLogsByTimeRange(ctx, startTime, endTime, req)
```

## Audit Actions

The service provides predefined constants for common audit actions:

### User Actions
- `ActionUserRegister` - User registration
- `ActionUserLogin` - Successful login
- `ActionUserLoginFailed` - Failed login attempt
- `ActionUserLogout` - User logout
- `ActionUserProfileUpdate` - Profile updates
- `ActionUserPasswordChange` - Password changes
- `ActionUserDelete` - User deletion
- `ActionUserLock` - Account lockout
- `ActionUserUnlock` - Account unlock

### Token Actions
- `ActionTokenGenerate` - Token generation
- `ActionTokenRefresh` - Token refresh
- `ActionTokenRevoke` - Token revocation
- `ActionTokenValidate` - Token validation

### Role Actions
- `ActionRoleCreate` - Role creation
- `ActionRoleUpdate` - Role modification
- `ActionRoleDelete` - Role deletion
- `ActionRoleAssign` - Role assignment
- `ActionRoleUnassign` - Role removal

### MFA Actions
- `ActionMFAEnable` - MFA setup
- `ActionMFADisable` - MFA removal
- `ActionMFAVerify` - MFA verification

### Security Actions
- `ActionRateLimitExceeded` - Rate limit violations
- `ActionSuspiciousActivity` - Suspicious behavior detection
- `ActionAccountLockout` - Security-based lockouts

### Administrative Actions
- `ActionAdminUserCreate` - Admin user creation
- `ActionAdminUserUpdate` - Admin user updates
- `ActionAdminUserDelete` - Admin user deletion
- `ActionAdminConfigUpdate` - Configuration changes
- `ActionAdminSystemAccess` - Admin system access

## Resource Types

Common resource types for categorizing audit events:

- `ResourceTypeUser` - User-related resources
- `ResourceTypeRole` - Role and permission resources
- `ResourceTypeSession` - Session resources
- `ResourceTypeToken` - Token resources
- `ResourceTypeMFA` - Multi-factor authentication resources
- `ResourceTypeConfig` - Configuration resources
- `ResourceTypeSystem` - System-level resources

## Metadata Best Practices

### Include Relevant Context
```go
metadata := map[string]interface{}{
    "ip_address":      clientIP,
    "user_agent":      userAgent,
    "session_id":      sessionID,
    "request_id":      requestID,
    "timestamp":       time.Now().Unix(),
}
```

### Security Events
```go
metadata := map[string]interface{}{
    "risk_score":      85,
    "threat_type":     "brute_force",
    "attempt_count":   5,
    "blocked":         true,
    "action_taken":    "account_locked",
}
```

### Administrative Actions
```go
metadata := map[string]interface{}{
    "admin_user_id":   adminID,
    "target_user_id":  targetUserID,
    "changes":         []string{"email", "role"},
    "previous_values": map[string]interface{}{
        "email": "old@example.com",
        "role":  "user",
    },
    "new_values": map[string]interface{}{
        "email": "new@example.com",
        "role":  "admin",
    },
}
```

## Database Schema

The audit service uses the `audit_logs` table:

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
```

## Performance Considerations

### Indexing
- User ID index for user-specific queries
- Timestamp index for time-range queries
- Action index for action-specific queries
- Consider composite indexes for common query patterns

### Pagination
- Always use pagination for large result sets
- Maximum limit of 1000 records per request
- Use offset-based pagination for consistency

### Cleanup
- Implement regular cleanup of old audit logs
- Consider archiving instead of deletion for compliance
- Use the `CleanupOldLogs` method for automated cleanup

```go
// Cleanup logs older than 1 year
oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
err := auditService.CleanupOldLogs(ctx, oneYearAgo)
```

## Integration with Other Services

### Authentication Service Integration
```go
// In your auth service
func (s *authService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
    // ... authentication logic ...
    
    // Log successful login
    auditEvent := audit.AuditEvent{
        UserID:       user.ID,
        Action:       audit.ActionUserLogin,
        ResourceType: audit.ResourceTypeUser,
        ResourceID:   user.ID.String(),
        IPAddress:    getClientIP(ctx),
        UserAgent:    getUserAgent(ctx),
        Metadata: map[string]interface{}{
            "login_method": "password",
            "success":      true,
        },
    }
    
    s.auditService.LogEvent(ctx, auditEvent)
    
    return response, nil
}
```

### Middleware Integration
```go
// Audit middleware for HTTP requests
func AuditMiddleware(auditService audit.AuditService) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        // Log request after processing
        if userID, exists := c.Get("user_id"); exists {
            event := audit.AuditEvent{
                UserID:    userID.(uuid.UUID),
                Action:    "api.request",
                IPAddress: getClientIP(c),
                UserAgent: c.GetHeader("User-Agent"),
                Metadata: map[string]interface{}{
                    "method":      c.Request.Method,
                    "path":        c.Request.URL.Path,
                    "status_code": c.Writer.Status(),
                    "duration":    time.Since(start).String(),
                },
            }
            auditService.LogEvent(c.Request.Context(), event)
        }
    }
}
```

## Testing

### Unit Tests
Run unit tests with:
```bash
go test ./internal/service/audit/
```

### Integration Tests
Run integration tests with a test database:
```bash
TEST_DATABASE_URL="postgres://user:pass@localhost/testdb" go test -tags=integration ./internal/service/audit/
```

## Security Considerations

### Data Protection
- Audit logs contain sensitive information and should be protected
- Consider encrypting sensitive metadata fields
- Implement proper access controls for audit log access

### Immutability
- Audit logs should never be modified after creation
- Implement database-level constraints to prevent modifications
- Consider using append-only storage for critical environments

### Compliance
- Ensure audit logging meets regulatory requirements (SOX, GDPR, etc.)
- Implement proper retention policies
- Consider geographic data residency requirements

## Monitoring and Alerting

### Key Metrics
- Audit log creation rate
- Failed audit log attempts
- Query performance metrics
- Storage growth rate

### Alerting
- Failed login attempts exceeding threshold
- Suspicious activity patterns
- Administrative action alerts
- System access violations

## Troubleshooting

### Common Issues

**High Database Load**
- Check query performance and indexing
- Implement connection pooling
- Consider read replicas for queries

**Storage Growth**
- Implement log rotation and archiving
- Monitor disk usage
- Optimize metadata storage

**Missing Audit Logs**
- Check service integration points
- Verify error handling in logging code
- Monitor audit service health

### Debug Logging
Enable debug logging to troubleshoot issues:
```go
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
```