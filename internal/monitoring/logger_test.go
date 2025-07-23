package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name   string
		config LoggerConfig
		want   bool
	}{
		{
			name: "json format",
			config: LoggerConfig{
				Level:  LogLevelInfo,
				Format: LogFormatJSON,
				Output: "stdout",
			},
			want: true,
		},
		{
			name: "text format",
			config: LoggerConfig{
				Level:  LogLevelDebug,
				Format: LogFormatText,
				Output: "stderr",
			},
			want: true,
		},
		{
			name:   "default values",
			config: LoggerConfig{},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(tt.config)
			if tt.want {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
				assert.Equal(t, tt.config.Level, logger.level)
				assert.Equal(t, tt.config.Format, logger.format)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestLogger_WithContext(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	// Create context with values
	ctx := context.Background()
	ctx = context.WithValue(ctx, "trace_id", "trace-123")
	ctx = context.WithValue(ctx, "user_id", "user-456")
	ctx = context.WithValue(ctx, "request_id", "req-789")

	contextLogger := logger.WithContext(ctx)
	assert.NotNil(t, contextLogger)
	assert.NotEqual(t, logger.Logger, contextLogger.Logger)
}

func TestLogger_WithFields(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	fieldsLogger := logger.WithFields(fields)
	assert.NotNil(t, fieldsLogger)
	assert.NotEqual(t, logger.Logger, fieldsLogger.Logger)
}

func TestLogger_WithError(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	testErr := errors.New("test error")
	errorLogger := logger.WithError(testErr)
	assert.NotNil(t, errorLogger)
	assert.NotEqual(t, logger.Logger, errorLogger.Logger)

	// Test with nil error
	nilErrorLogger := logger.WithError(nil)
	assert.Equal(t, logger, nilErrorLogger)
}

func TestLogger_AuthEvent(t *testing.T) {
	// var buf bytes.Buffer
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}

	// We can't easily capture the output in this test setup
	// In a real test, you'd redirect the output to a buffer
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"method": "password",
		"ip":     "192.168.1.1",
	}

	// Test successful auth event
	logger.AuthEvent(ctx, "login", "user123", true, details)

	// Test failed auth event
	logger.AuthEvent(ctx, "login", "user123", false, details)

	// These calls should not panic
	assert.NotNil(t, logger)
}

func TestLogger_SecurityEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"ip":     "192.168.1.1",
		"reason": "multiple_failed_attempts",
	}

	// Test different severity levels
	severities := []string{"low", "medium", "high", "critical", "unknown"}
	for _, severity := range severities {
		logger.SecurityEvent(ctx, "suspicious_activity", severity, details)
	}

	assert.NotNil(t, logger)
}

func TestLogger_AuditEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"old_value": "old",
		"new_value": "new",
	}

	logger.AuditEvent(ctx, "update_profile", "user", "user123", details)
	assert.NotNil(t, logger)
}

func TestLogger_PerformanceEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"query": "SELECT * FROM users",
	}

	// Test different durations
	durations := []time.Duration{
		100 * time.Millisecond, // Should log as debug
		2 * time.Second,        // Should log as info
		6 * time.Second,        // Should log as warning
	}

	for _, duration := range durations {
		logger.PerformanceEvent(ctx, "database_query", duration, details)
	}

	assert.NotNil(t, logger)
}

func TestLogger_DatabaseEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test successful database operation
	logger.DatabaseEvent(ctx, "SELECT", "users", 100*time.Millisecond, nil)

	// Test failed database operation
	dbErr := errors.New("connection timeout")
	logger.DatabaseEvent(ctx, "INSERT", "users", 5*time.Second, dbErr)

	// Test slow database operation
	logger.DatabaseEvent(ctx, "SELECT", "users", 2*time.Second, nil)

	assert.NotNil(t, logger)
}

func TestLogger_CacheEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test cache hit
	logger.CacheEvent(ctx, "get", "user:123", true, 10*time.Millisecond)

	// Test cache miss
	logger.CacheEvent(ctx, "get", "user:456", false, 5*time.Millisecond)

	assert.NotNil(t, logger)
}

func TestLogger_HTTPEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test different HTTP status codes
	testCases := []struct {
		statusCode int
		method     string
		path       string
	}{
		{200, "GET", "/api/users"},
		{400, "POST", "/api/login"},
		{500, "GET", "/api/internal"},
	}

	for _, tc := range testCases {
		logger.HTTPEvent(ctx, tc.method, tc.path, tc.statusCode, 100*time.Millisecond, "test-agent", "192.168.1.1")
	}

	assert.NotNil(t, logger)
}

func TestLogger_GRPCEvent(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test successful gRPC call
	logger.GRPCEvent(ctx, "AuthService", "Login", "OK", 150*time.Millisecond, "192.168.1.1")

	// Test failed gRPC call
	logger.GRPCEvent(ctx, "AuthService", "Login", "InvalidArgument", 50*time.Millisecond, "192.168.1.1")

	assert.NotNil(t, logger)
}

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level LogLevel
		want  string
	}{
		{LogLevelDebug, "debug"},
		{LogLevelInfo, "info"},
		{LogLevelWarn, "warn"},
		{LogLevelError, "error"},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.level))
		})
	}
}

func TestLogFormat_String(t *testing.T) {
	tests := []struct {
		format LogFormat
		want   string
	}{
		{LogFormatJSON, "json"},
		{LogFormatText, "text"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.format))
		})
	}
}

func TestLogger_MarshalJSON(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	data, err := json.Marshal(logger)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "info")
	assert.Contains(t, string(data), "json")
}

func TestLogger_Close(t *testing.T) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)

	err = logger.Close()
	assert.NoError(t, err)
}

func TestGetStackTrace(t *testing.T) {
	trace := getStackTrace()
	assert.NotEmpty(t, trace)
	assert.True(t, strings.Contains(trace, "monitoring") || strings.Contains(trace, "test"))
}

// Benchmark tests
func BenchmarkLogger_Info(b *testing.B) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark test message")
	}
}

func BenchmarkLogger_WithFields(b *testing.B) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(b, err)

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithFields(fields).Info("benchmark test message")
	}
}

func BenchmarkLogger_AuthEvent(b *testing.B) {
	config := LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	}
	logger, err := NewLogger(config)
	require.NoError(b, err)

	ctx := context.Background()
	details := map[string]interface{}{
		"method": "password",
		"ip":     "192.168.1.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.AuthEvent(ctx, "login", "user123", true, details)
	}
}
