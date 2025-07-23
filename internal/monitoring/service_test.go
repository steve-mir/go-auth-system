package monitoring

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "disabled service",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled service with all features",
			config: Config{
				Enabled: true,
				Prometheus: PrometheusConfig{
					Enabled: true,
					Path:    "/metrics",
					Port:    9090,
				},
				Logging: LoggerConfig{
					Level:             LogLevelInfo,
					Format:            LogFormatJSON,
					Output:            "stdout",
					EnableTracing:     true,
					EnableCorrelation: true,
					ServiceName:       "test-service",
					ServiceVersion:    "1.0.0",
				},
				ErrorTracker: ErrorTrackerConfig{
					Enabled:          true,
					MaxErrors:        1000,
					RetentionPeriod:  24 * time.Hour,
					AlertingEnabled:  true,
					AlertBuffer:      100,
					DefaultSeverity:  SeverityMedium,
					EnableStackTrace: true,
					EnableGrouping:   true,
				},
				Aggregator: LogAggregatorConfig{
					Enabled:           true,
					MaxEntries:        1000,
					RetentionPeriod:   24 * time.Hour,
					AggregationLevels: []string{"minute", "hour"},
					PatternDetection:  true,
					MetricsEnabled:    true,
				},
				Tracing: TracingConfig{
					Enabled:        true,
					ServiceName:    "test-service",
					ServiceVersion: "1.0.0",
					SampleRate:     1.0,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewService(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && service == nil {
				t.Error("NewService() returned nil service")
			}

			if tt.config.Enabled {
				if service.logger == nil {
					t.Error("Expected logger to be initialized")
				}
				if service.metrics == nil {
					t.Error("Expected metrics to be initialized")
				}
				if tt.config.ErrorTracker.Enabled && service.errorTracker == nil {
					t.Error("Expected error tracker to be initialized")
				}
				if tt.config.Aggregator.Enabled && service.aggregator == nil {
					t.Error("Expected log aggregator to be initialized")
				}
			}
		})
	}
}

func TestService_GetComponents(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       1000,
			RetentionPeriod: 24 * time.Hour,
		},
		Aggregator: LogAggregatorConfig{
			Enabled:         true,
			MaxEntries:      1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	if service.GetLogger() == nil {
		t.Error("GetLogger() returned nil")
	}

	if service.GetMetrics() == nil {
		t.Error("GetMetrics() returned nil")
	}

	if service.GetRegistry() == nil {
		t.Error("GetRegistry() returned nil")
	}

	if service.GetErrorTracker() == nil {
		t.Error("GetErrorTracker() returned nil")
	}

	if service.GetLogAggregator() == nil {
		t.Error("GetLogAggregator() returned nil")
	}
}

func TestService_TrackError(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.WithValue(context.Background(), "user_id", "user-123")
	testErr := errors.New("test error")
	category := CategoryDatabase
	operation := "SELECT"
	component := "postgres"

	errorID := service.TrackError(ctx, testErr, category, operation, component)

	if errorID == "" {
		t.Error("TrackError() returned empty error ID")
	}

	// Verify error was tracked
	errors := service.GetErrors(category, "", nil)
	if len(errors) != 1 {
		t.Errorf("Expected 1 tracked error, got %d", len(errors))
	}
}

func TestService_StartFinishTrace(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:         LogLevelDebug,
			Format:        LogFormatJSON,
			Output:        "stdout",
			EnableTracing: true,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()
	operation := "test_operation"

	// Start trace
	trace, newCtx := service.StartTrace(ctx, operation)

	if trace == nil {
		t.Error("StartTrace() returned nil trace")
	}

	if trace.Operation != operation {
		t.Errorf("Expected operation %s, got %s", operation, trace.Operation)
	}

	// Add trace tag
	service.AddTraceTag(newCtx, "test_key", "test_value")

	if trace.Tags["test_key"] != "test_value" {
		t.Error("AddTraceTag() did not set tag correctly")
	}

	// Finish trace
	time.Sleep(10 * time.Millisecond) // Ensure measurable duration
	service.FinishTrace(newCtx, trace, nil)

	if !trace.Finished {
		t.Error("Trace should be finished")
	}

	if trace.Duration == 0 {
		t.Error("Trace duration should be greater than 0")
	}
}

func TestService_CreateCorrelation(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:             LogLevelInfo,
			Format:            LogFormatJSON,
			Output:            "stdout",
			EnableCorrelation: true,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	requestID := "req-123"
	sessionID := "sess-456"
	userID := "user-789"
	clientIP := "192.168.1.1"
	userAgent := "test-agent"

	correlation := service.CreateCorrelation(requestID, sessionID, userID, clientIP, userAgent)

	if correlation == nil {
		t.Error("CreateCorrelation() returned nil")
	}

	if correlation.RequestID != requestID {
		t.Errorf("Expected RequestID %s, got %s", requestID, correlation.RequestID)
	}

	// Test WithCorrelation
	ctx := context.Background()
	newCtx := service.WithCorrelation(ctx, correlation)

	if corrID := newCtx.Value("correlation_id"); corrID != correlation.CorrelationID {
		t.Error("WithCorrelation() did not set correlation_id in context")
	}
}

func TestService_SearchLogs(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		Aggregator: LogAggregatorConfig{
			Enabled:         true,
			MaxEntries:      1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Add test log entry
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "test message",
		EventType: "http",
		Component: "api",
		UserID:    "user-123",
	}

	service.aggregator.AddLogEntry(entry)

	// Search logs
	query := LogSearchQuery{
		Level:  "info",
		UserID: "user-123",
	}

	results := service.SearchLogs(query)

	if len(results) != 1 {
		t.Errorf("Expected 1 search result, got %d", len(results))
	}

	if results[0].Message != "test message" {
		t.Errorf("Expected message 'test message', got %s", results[0].Message)
	}
}

func TestService_GetLogStatistics(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		Aggregator: LogAggregatorConfig{
			Enabled:         true,
			MaxEntries:      1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Add test log entries
	entries := []LogEntry{
		{
			Timestamp: time.Now(),
			Level:     "info",
			EventType: "http",
			Component: "api",
			Duration:  100.0,
		},
		{
			Timestamp: time.Now(),
			Level:     "error",
			EventType: "database",
			Component: "postgres",
			Duration:  200.0,
			Error:     "connection failed",
		},
	}

	for _, entry := range entries {
		service.aggregator.AddLogEntry(entry)
	}

	stats := service.GetLogStatistics(time.Time{}, time.Time{})

	if stats == nil {
		t.Error("GetLogStatistics() returned nil")
	}

	if stats.TotalEntries != 2 {
		t.Errorf("Expected 2 total entries, got %d", stats.TotalEntries)
	}

	if stats.LevelCounts["info"] != 1 {
		t.Errorf("Expected 1 info log, got %d", stats.LevelCounts["info"])
	}

	if stats.LevelCounts["error"] != 1 {
		t.Errorf("Expected 1 error log, got %d", stats.LevelCounts["error"])
	}

	if stats.ErrorRate != 50.0 {
		t.Errorf("Expected error rate 50%%, got %.1f%%", stats.ErrorRate)
	}
}

func TestService_GetErrors(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()
	testErr := errors.New("test error")
	category := CategoryDatabase

	// Track an error
	errorID := service.TrackError(ctx, testErr, category, "test", "test")

	// Get errors
	errors := service.GetErrors(category, "", nil)

	if len(errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(errors))
	}

	if errors[0].ID != errorID {
		t.Error("Retrieved error ID does not match tracked error ID")
	}

	// Test resolving error
	service.ResolveError(errorID, "admin-123")

	resolved := true
	resolvedErrors := service.GetErrors("", "", &resolved)

	if len(resolvedErrors) != 1 {
		t.Errorf("Expected 1 resolved error, got %d", len(resolvedErrors))
	}

	if !resolvedErrors[0].Resolved {
		t.Error("Error should be marked as resolved")
	}
}

func TestService_AddErrorContext(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()
	testErr := errors.New("test error")
	errorID := service.TrackError(ctx, testErr, CategorySystem, "test", "test")

	key := "additional_info"
	value := "test context value"
	service.AddErrorContext(errorID, key, value)

	errors := service.GetErrors("", "", nil)
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(errors))
	}

	if errors[0].Context[key] != value {
		t.Errorf("Expected context value %s, got %v", value, errors[0].Context[key])
	}
}

func TestService_ExportLogMetrics(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		Aggregator: LogAggregatorConfig{
			Enabled:         true,
			MaxEntries:      1000,
			RetentionPeriod: 24 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Add a test metric manually
	metric := &LogMetric{
		Timestamp: time.Now(),
		Level:     AggregationMinute,
		EventType: "http",
		Component: "api",
		Count:     10,
	}

	service.aggregator.mu.Lock()
	service.aggregator.metrics["test_metric"] = metric
	service.aggregator.mu.Unlock()

	// Test export
	data, err := service.ExportLogMetrics("json")
	if err != nil {
		t.Errorf("ExportLogMetrics() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected exported data to not be empty")
	}
}

func TestService_GetAlerts(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       1000,
			RetentionPeriod: 24 * time.Hour,
			AlertingEnabled: true,
			AlertBuffer:     100,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Manually add an alert for testing
	alert := &Alert{
		ID:         "test_alert",
		RuleID:     "test_rule",
		RuleName:   "Test Rule",
		Timestamp:  time.Now(),
		Severity:   SeverityHigh,
		Message:    "Test alert",
		ErrorCount: 5,
		Resolved:   false,
	}

	service.errorTracker.mu.Lock()
	service.errorTracker.alerts[alert.ID] = alert
	service.errorTracker.mu.Unlock()

	alerts := service.GetAlerts(nil)

	if len(alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(alerts))
	}

	if alerts[0].ID != alert.ID {
		t.Error("Retrieved alert ID does not match")
	}
}

func TestService_GetAlertChannel(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       1000,
			RetentionPeriod: 24 * time.Hour,
			AlertingEnabled: true,
			AlertBuffer:     100,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	alertChan := service.GetAlertChannel()

	if alertChan == nil {
		t.Error("GetAlertChannel() returned nil")
	}
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
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()
	err = service.HealthCheck(ctx)

	if err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
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
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	err = service.Close()

	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestService_DisabledComponents(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled: false,
		},
		Aggregator: LogAggregatorConfig{
			Enabled: false,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Test that disabled components return nil
	if service.GetErrorTracker() != nil {
		t.Error("Expected error tracker to be nil when disabled")
	}

	if service.GetLogAggregator() != nil {
		t.Error("Expected log aggregator to be nil when disabled")
	}

	// Test that methods handle nil components gracefully
	ctx := context.Background()
	testErr := errors.New("test error")

	errorID := service.TrackError(ctx, testErr, CategorySystem, "test", "test")
	if errorID != "" {
		t.Error("Expected empty error ID when error tracker is disabled")
	}

	results := service.SearchLogs(LogSearchQuery{})
	if results != nil {
		t.Error("Expected nil search results when log aggregator is disabled")
	}

	stats := service.GetLogStatistics(time.Time{}, time.Time{})
	if stats != nil {
		t.Error("Expected nil statistics when log aggregator is disabled")
	}
}
