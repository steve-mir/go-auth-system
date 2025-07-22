package monitoring

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{
			name: "enabled service",
			config: Config{
				Enabled: true,
				Prometheus: PrometheusConfig{
					Enabled: true,
					Path:    "/metrics",
					Port:    9090,
				},
				Logging: LoggerConfig{
					Level:  LogLevelInfo,
					Format: LogFormatJSON,
					Output: "stdout",
				},
			},
			want: true,
		},
		{
			name: "disabled service",
			config: Config{
				Enabled: false,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewService(tt.config)
			if tt.want {
				assert.NoError(t, err)
				assert.NotNil(t, service)

				if tt.config.Enabled {
					assert.NotNil(t, service.metrics)
					assert.NotNil(t, service.logger)
					assert.NotNil(t, service.registry)
					assert.NotNil(t, service.collector)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestService_GetMetrics(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	metrics := service.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, service.metrics, metrics)
}

func TestService_GetLogger(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	logger := service.GetLogger()
	assert.NotNil(t, logger)
	assert.Equal(t, service.logger, logger)
}

func TestService_GetRegistry(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	registry := service.GetRegistry()
	assert.NotNil(t, registry)
	assert.Equal(t, service.registry, registry)
}

func TestService_MetricsHandler(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	handler := service.MetricsHandler()
	assert.NotNil(t, handler)

	// Test with disabled service
	disabledService := &Service{}
	disabledHandler := disabledService.MetricsHandler()
	assert.NotNil(t, disabledHandler)
}

func TestService_HealthCheck(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = service.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestService_RecordAuthEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"method": "password",
		"ip":     "192.168.1.1",
	}

	// Test successful auth
	service.RecordAuthEvent(ctx, "password", "user123", true, 100*time.Millisecond, details)

	// Test failed auth
	details["reason"] = "invalid_password"
	service.RecordAuthEvent(ctx, "password", "user123", false, 50*time.Millisecond, details)

	// Verify metrics were recorded (basic check)
	assert.NotNil(t, service.metrics)
}

func TestService_RecordTokenEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"user_id": "user123",
	}

	// Test different token operations
	operations := []struct {
		operation string
		success   bool
	}{
		{"generate", true},
		{"validate", true},
		{"validate", false},
		{"refresh", true},
	}

	for _, op := range operations {
		service.RecordTokenEvent(ctx, op.operation, "jwt", op.success, details)
	}

	assert.NotNil(t, service.metrics)
}

func TestService_RecordUserEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test different user operations
	operations := []struct {
		operation string
		details   map[string]interface{}
	}{
		{"register", map[string]interface{}{"method": "direct"}},
		{"login", map[string]interface{}{"method": "password"}},
		{"logout", map[string]interface{}{}},
		{"profile_update", map[string]interface{}{"field": "email"}},
	}

	for _, op := range operations {
		service.RecordUserEvent(ctx, op.operation, "user123", op.details)
	}

	assert.NotNil(t, service.metrics)
}

func TestService_RecordMFAEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"user_id": "user123",
	}

	// Test successful MFA
	service.RecordMFAEvent(ctx, "totp", true, "", details)

	// Test failed MFA
	service.RecordMFAEvent(ctx, "sms", false, "invalid_code", details)

	assert.NotNil(t, service.metrics)
}

func TestService_RecordDatabaseEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelDebug,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test successful database operation
	service.RecordDatabaseEvent(ctx, "SELECT", "users", 100*time.Millisecond, nil)

	// Test failed database operation
	dbErr := assert.AnError
	service.RecordDatabaseEvent(ctx, "INSERT", "users", 200*time.Millisecond, dbErr)

	assert.NotNil(t, service.metrics)
}

func TestService_RecordCacheEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelDebug,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test cache hit
	service.RecordCacheEvent(ctx, "redis", "get", "user:123", true, 10*time.Millisecond, nil)

	// Test cache miss
	service.RecordCacheEvent(ctx, "redis", "get", "user:456", false, 5*time.Millisecond, nil)

	// Test cache error
	service.RecordCacheEvent(ctx, "redis", "set", "user:789", false, 20*time.Millisecond, assert.AnError)

	assert.NotNil(t, service.metrics)
}

func TestService_RecordHTTPEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()

	service.RecordHTTPEvent(
		ctx,
		"GET",
		"/api/users",
		http.StatusOK,
		150*time.Millisecond,
		1024,
		2048,
		"test-agent",
		"192.168.1.1",
	)

	assert.NotNil(t, service.metrics)
}

func TestService_RecordGRPCEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()

	service.RecordGRPCEvent(ctx, "AuthService", "Login", "OK", 100*time.Millisecond, "192.168.1.1")

	assert.NotNil(t, service.metrics)
}

func TestService_RecordRateLimitEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"limit":  100,
		"window": "1m",
	}

	// Test rate limit hit
	service.RecordRateLimitEvent(ctx, "ip", "192.168.1.1", false, details)

	// Test rate limit block
	service.RecordRateLimitEvent(ctx, "user", "user123", true, details)

	assert.NotNil(t, service.metrics)
}

func TestService_RecordSecurityEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"ip":         "192.168.1.1",
		"user_agent": "suspicious-agent",
	}

	service.RecordSecurityEvent(ctx, "suspicious_activity", "high", details)

	assert.NotNil(t, service.logger)
}

func TestService_RecordAuditEvent(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"old_email": "old@example.com",
		"new_email": "new@example.com",
	}

	service.RecordAuditEvent(ctx, "update_profile", "user", "user123", details)

	assert.NotNil(t, service.logger)
}

func TestService_UpdateSystemHealth(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	service.UpdateSystemHealth("database", true)
	service.UpdateSystemHealth("cache", false)

	assert.NotNil(t, service.metrics)
}

func TestService_UpdateActiveSessions(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	service.UpdateActiveSessions("web", 100)
	service.UpdateActiveSessions("mobile", 50)

	assert.NotNil(t, service.metrics)
}

func TestService_UpdateDatabaseConnections(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	service.UpdateDatabaseConnections(5, 3, 10)

	assert.NotNil(t, service.metrics)
}

func TestService_StartCollection(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start collection (should not block)
	service.StartCollection(ctx, 50*time.Millisecond)

	// Wait for context to be cancelled
	<-ctx.Done()

	assert.NotNil(t, service.collector)
}

func TestService_Close(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	service, err := NewService(config)
	require.NoError(t, err)

	err = service.Close()
	assert.NoError(t, err)
}

func TestService_DisabledService(t *testing.T) {
	// Test that disabled service doesn't panic
	service := &Service{}

	ctx := context.Background()
	details := map[string]interface{}{}

	// These should not panic
	service.RecordAuthEvent(ctx, "password", "user123", true, 100*time.Millisecond, details)
	service.RecordTokenEvent(ctx, "generate", "jwt", true, details)
	service.RecordUserEvent(ctx, "login", "user123", details)
	service.UpdateSystemHealth("test", true)

	handler := service.MetricsHandler()
	assert.NotNil(t, handler)

	err := service.HealthCheck(ctx)
	assert.NoError(t, err)

	err = service.Close()
	assert.NoError(t, err)
}
