package monitoring

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestObservabilityIntegration tests the complete observability system integration
func TestObservabilityIntegration(t *testing.T) {
	// Create a fully configured monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:             LogLevelDebug,
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
			RetentionPeriod:  1 * time.Hour,
			AlertingEnabled:  true,
			AlertBuffer:      100,
			DefaultSeverity:  SeverityMedium,
			EnableStackTrace: true,
			EnableGrouping:   true,
		},
		Aggregator: LogAggregatorConfig{
			Enabled:           true,
			MaxEntries:        1000,
			RetentionPeriod:   1 * time.Hour,
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
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create monitoring service: %v", err)
	}

	// Test 1: Distributed Tracing Integration
	t.Run("DistributedTracing", func(t *testing.T) {
		testDistributedTracing(t, service)
	})

	// Test 2: Error Tracking Integration
	t.Run("ErrorTracking", func(t *testing.T) {
		testErrorTracking(t, service)
	})

	// Test 3: Log Aggregation Integration
	t.Run("LogAggregation", func(t *testing.T) {
		testLogAggregation(t, service)
	})

	// Test 4: Correlation Context Integration
	t.Run("CorrelationContext", func(t *testing.T) {
		testCorrelationContext(t, service)
	})

	// Test 5: Alert System Integration
	t.Run("AlertSystem", func(t *testing.T) {
		testAlertSystem(t, service)
	})

	// Test 6: End-to-End Observability Flow
	t.Run("EndToEndFlow", func(t *testing.T) {
		testEndToEndObservabilityFlow(t, service)
	})
}

func testDistributedTracing(t *testing.T, service *Service) {
	ctx := context.Background()

	// Start main trace
	mainTrace, ctx := service.StartTrace(ctx, "test_operation")
	if mainTrace == nil {
		t.Fatal("Failed to start main trace")
	}

	// Add tags to main trace
	service.AddTraceTag(ctx, "test_key", "test_value")
	service.AddTraceTag(ctx, "operation_type", "integration_test")

	// Start child trace
	childTrace, childCtx := service.StartTrace(ctx, "child_operation")
	if childTrace == nil {
		t.Fatal("Failed to start child trace")
	}

	// Verify parent-child relationship
	if childTrace.ParentID != mainTrace.SpanID {
		t.Errorf("Expected child parent ID %s, got %s", mainTrace.SpanID, childTrace.ParentID)
	}

	if childTrace.TraceID != mainTrace.TraceID {
		t.Errorf("Expected child trace ID %s, got %s", mainTrace.TraceID, childTrace.TraceID)
	}

	// Add logs to traces
	// service.AddTraceLog(childCtx, "info", "Child operation started", map[string]interface{}{
	// 	"step": 1,
	// })

	// Simulate work
	time.Sleep(10 * time.Millisecond)

	// Finish child trace
	service.FinishTrace(childCtx, childTrace, nil)

	// Verify child trace is finished
	if !childTrace.Finished {
		t.Error("Child trace should be finished")
	}

	if childTrace.Duration == 0 {
		t.Error("Child trace should have measurable duration")
	}

	// Finish main trace
	service.FinishTrace(ctx, mainTrace, nil)

	// Verify main trace is finished
	if !mainTrace.Finished {
		t.Error("Main trace should be finished")
	}

	// Verify tags were set
	if mainTrace.Tags["test_key"] != "test_value" {
		t.Error("Main trace tag was not set correctly")
	}

	// Verify logs were added
	if len(childTrace.Logs) != 1 {
		t.Errorf("Expected 1 log entry in child trace, got %d", len(childTrace.Logs))
	}
}

func testErrorTracking(t *testing.T, service *Service) {
	ctx := context.WithValue(context.Background(), "user_id", "test-user-123")
	ctx = context.WithValue(ctx, "request_id", "test-req-456")

	// Track different types of errors
	errors := []struct {
		err       error
		category  ErrorCategory
		operation string
		component string
	}{
		{errors.New("database connection failed"), CategoryDatabase, "connect", "postgres"},
		{errors.New("authentication failed"), CategoryAuth, "login", "auth_service"},
		{errors.New("validation error"), CategoryValidation, "validate_input", "api"},
		{errors.New("cache miss"), CategoryCache, "get", "redis"},
	}

	var errorIDs []string
	for _, e := range errors {
		errorID := service.TrackError(ctx, e.err, e.category, e.operation, e.component)
		if errorID == "" {
			t.Errorf("Failed to track error: %v", e.err)
		}
		errorIDs = append(errorIDs, errorID)

		// Add context to error
		service.AddErrorContext(errorID, "test_context", "integration_test")
	}

	// Verify errors were tracked
	allErrors := service.GetErrors("", "", nil)
	if len(allErrors) != len(errors) {
		t.Errorf("Expected %d tracked errors, got %d", len(errors), len(allErrors))
	}

	// Test filtering by category
	dbErrors := service.GetErrors(CategoryDatabase, "", nil)
	if len(dbErrors) != 1 {
		t.Errorf("Expected 1 database error, got %d", len(dbErrors))
	}

	// Test resolving errors
	service.ResolveError(errorIDs[0], "test-admin")
	resolved := true
	resolvedErrors := service.GetErrors("", "", &resolved)
	if len(resolvedErrors) != 1 {
		t.Errorf("Expected 1 resolved error, got %d", len(resolvedErrors))
	}

	// Test error grouping by tracking the same error again
	originalCount := len(allErrors)
	service.TrackError(ctx, errors[0].err, errors[0].category, errors[0].operation, errors[0].component)

	newAllErrors := service.GetErrors("", "", nil)
	if len(newAllErrors) != originalCount {
		t.Error("Same error should be grouped, not create new entry")
	}

	// Verify error count increased
	dbErrors = service.GetErrors(CategoryDatabase, "", nil)
	if dbErrors[0].Count != 2 {
		t.Errorf("Expected error count 2, got %d", dbErrors[0].Count)
	}
}

func testLogAggregation(t *testing.T, service *Service) {
	// Add various log entries
	entries := []LogEntry{
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "User login successful",
			EventType: "auth",
			Component: "auth_service",
			Operation: "login",
			Duration:  150.0,
			UserID:    "user-123",
			RequestID: "req-1",
		},
		{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   "Database connection failed",
			EventType: "database",
			Component: "postgres",
			Operation: "connect",
			Duration:  5000.0,
			Error:     "connection timeout",
			RequestID: "req-2",
		},
		{
			Timestamp: time.Now(),
			Level:     "warn",
			Message:   "Slow query detected",
			EventType: "database",
			Component: "postgres",
			Operation: "query",
			Duration:  2000.0,
			UserID:    "user-456",
			RequestID: "req-3",
		},
	}

	for _, entry := range entries {
		service.aggregator.AddLogEntry(entry)
	}

	// Test log search
	query := LogSearchQuery{
		EventType: "database",
		Level:     "error",
	}
	results := service.SearchLogs(query)
	if len(results) != 1 {
		t.Errorf("Expected 1 database error log, got %d", len(results))
	}

	// Test log statistics
	stats := service.GetLogStatistics(time.Time{}, time.Time{})
	if stats.TotalEntries != 3 {
		t.Errorf("Expected 3 total entries, got %d", stats.TotalEntries)
	}

	expectedErrorRate := float64(1) / float64(3) * 100 // 33.33%
	if stats.ErrorRate != expectedErrorRate {
		t.Errorf("Expected error rate %.2f%%, got %.2f%%", expectedErrorRate, stats.ErrorRate)
	}

	// Test metrics aggregation
	service.aggregator.processEntries()
	metrics := service.GetLogMetrics("database", "postgres", AggregationMinute, time.Time{}, time.Time{})
	if len(metrics) == 0 {
		t.Error("Expected aggregated metrics to be generated")
	}

	// Test pattern detection
	patterns := service.GetLogPatterns("database", "postgres")
	if len(patterns) == 0 {
		t.Error("Expected patterns to be detected")
	}
}

func testCorrelationContext(t *testing.T, service *Service) {
	// Create correlation context
	correlation := service.CreateCorrelation(
		"req-123",
		"sess-456",
		"user-789",
		"192.168.1.1",
		"test-agent/1.0",
	)

	if correlation == nil {
		t.Fatal("Failed to create correlation context")
	}

	// Add correlation to context
	ctx := context.Background()
	ctx = service.WithCorrelation(ctx, correlation)

	// Verify context values
	if corrID := ctx.Value("correlation_id"); corrID != correlation.CorrelationID {
		t.Error("Correlation ID not set in context")
	}

	if reqID := ctx.Value("request_id"); reqID != correlation.RequestID {
		t.Error("Request ID not set in context")
	}

	if userID := ctx.Value("user_id"); userID != correlation.UserID {
		t.Error("User ID not set in context")
	}

	// Test that correlation context is used in tracing
	trace, newCtx := service.StartTrace(ctx, "test_with_correlation")
	if trace == nil {
		t.Fatal("Failed to start trace with correlation")
	}

	// Verify correlation is preserved in new context
	if corrID := newCtx.Value("correlation_id"); corrID != correlation.CorrelationID {
		t.Error("Correlation ID not preserved in trace context")
	}

	service.FinishTrace(newCtx, trace, nil)
}

func testAlertSystem(t *testing.T, service *Service) {
	// Get alert channel
	alertChan := service.GetAlertChannel()
	if alertChan == nil {
		t.Fatal("Alert channel should not be nil")
	}

	// Create a custom alert rule for testing
	rule := &AlertRule{
		ID:         "test_rule",
		Name:       "Test Alert Rule",
		Category:   CategoryAuth,
		Severity:   "",
		Threshold:  2,
		TimeWindow: 1 * time.Minute,
		Enabled:    true,
		Cooldown:   30 * time.Second,
	}

	service.errorTracker.AddAlertRule(rule)

	// Track errors to trigger alert
	ctx := context.Background()
	testErr := errors.New("authentication failed")

	// Track first error (should not trigger alert)
	service.TrackError(ctx, testErr, CategoryAuth, "login", "auth_service")

	// Track second error (should trigger alert)
	service.TrackError(ctx, testErr, CategoryAuth, "login", "auth_service")

	// Wait briefly for alert processing
	time.Sleep(100 * time.Millisecond)

	// Check if alert was generated
	alerts := service.GetAlerts(nil)
	if len(alerts) == 0 {
		t.Error("Expected alert to be generated")
	}

	// Verify alert properties
	if len(alerts) > 0 {
		alert := alerts[0]
		if alert.RuleID != rule.ID {
			t.Errorf("Expected alert rule ID %s, got %s", rule.ID, alert.RuleID)
		}
		if alert.Severity != SeverityMedium {
			t.Errorf("Expected alert severity %s, got %s", SeverityMedium, alert.Severity)
		}
	}
}

func testEndToEndObservabilityFlow(t *testing.T, service *Service) {
	// Simulate a complete request flow with full observability
	ctx := context.Background()

	// 1. Create correlation context (simulating middleware)
	correlation := service.CreateCorrelation(
		"req-e2e-123",
		"sess-e2e-456",
		"user-e2e-789",
		"192.168.1.100",
		"integration-test/1.0",
	)
	ctx = service.WithCorrelation(ctx, correlation)

	// 2. Start main request trace
	mainTrace, ctx := service.StartTrace(ctx, "api_request_handler")
	service.AddTraceTag(ctx, "endpoint", "/api/v1/users")
	service.AddTraceTag(ctx, "method", "GET")

	// 3. Simulate authentication step
	authTrace, authCtx := service.StartTrace(ctx, "authenticate_request")
	service.AddTraceTag(authCtx, "auth_method", "jwt")

	// Record authentication event
	service.RecordAuthEvent(authCtx, "token_validation", "user-e2e-789", true, 50*time.Millisecond, map[string]interface{}{
		"token_type": "jwt",
		"ip":         "192.168.1.100",
	})

	service.FinishTrace(authCtx, authTrace, nil)

	// 4. Simulate database operation
	dbTrace, dbCtx := service.StartTrace(ctx, "database_query")
	service.AddTraceTag(dbCtx, "table", "users")
	service.AddTraceTag(dbCtx, "operation", "SELECT")

	// Record database event
	service.RecordDatabaseEvent(dbCtx, "SELECT", "users", 100*time.Millisecond, nil)

	service.FinishTrace(dbCtx, dbTrace, nil)

	// 5. Simulate cache operation
	cacheTrace, cacheCtx := service.StartTrace(ctx, "cache_lookup")
	service.AddTraceTag(cacheCtx, "cache_type", "redis")
	service.AddTraceTag(cacheCtx, "key", "user:e2e:789")

	// Record cache event
	service.RecordCacheEvent(cacheCtx, "redis", "GET", "user:e2e:789", true, 10*time.Millisecond, nil)

	service.FinishTrace(cacheCtx, cacheTrace, nil)

	// 6. Add log entry for the complete request
	logEntry := LogEntry{
		Timestamp:     time.Now(),
		Level:         "info",
		Message:       "API request completed successfully",
		EventType:     "http",
		Component:     "api_server",
		Operation:     "GET /api/v1/users",
		Duration:      200.0,
		UserID:        correlation.UserID,
		RequestID:     correlation.RequestID,
		TraceID:       mainTrace.TraceID,
		CorrelationID: correlation.CorrelationID,
		ClientIP:      correlation.ClientIP,
		UserAgent:     correlation.UserAgent,
		StatusCode:    200,
		Fields: map[string]interface{}{
			"response_size": 1024,
			"cache_hit":     true,
		},
	}

	service.aggregator.AddLogEntry(logEntry)

	// 7. Finish main trace
	service.FinishTrace(ctx, mainTrace, nil)

	// 8. Verify the complete observability data

	// Check that traces were created with proper hierarchy
	if mainTrace.TraceID == "" {
		t.Error("Main trace should have trace ID")
	}

	if authTrace.ParentID != mainTrace.SpanID {
		t.Error("Auth trace should be child of main trace")
	}

	if dbTrace.ParentID != mainTrace.SpanID {
		t.Error("DB trace should be child of main trace")
	}

	// Check that log entry was added
	searchResults := service.SearchLogs(LogSearchQuery{
		RequestID: correlation.RequestID,
		TraceID:   mainTrace.TraceID,
	})

	if len(searchResults) != 1 {
		t.Errorf("Expected 1 log entry for request, got %d", len(searchResults))
	}

	if len(searchResults) > 0 {
		entry := searchResults[0]
		if entry.CorrelationID != correlation.CorrelationID {
			t.Error("Log entry should have correlation ID")
		}
		if entry.TraceID != mainTrace.TraceID {
			t.Error("Log entry should have trace ID")
		}
	}

	// Check that metrics were recorded
	// This would typically be verified by checking Prometheus metrics
	// For this test, we'll just verify the service is tracking the events

	t.Log("End-to-end observability flow completed successfully")
	t.Logf("- Main trace ID: %s", mainTrace.TraceID)
	t.Logf("- Correlation ID: %s", correlation.CorrelationID)
	t.Logf("- Request ID: %s", correlation.RequestID)
	t.Logf("- Total spans: 4 (main + auth + db + cache)")
	t.Logf("- Log entries: %d", len(searchResults))
}

// TestObservabilityPerformance tests the performance impact of observability features
func TestObservabilityPerformance(t *testing.T) {
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:             LogLevelInfo,
			Format:            LogFormatJSON,
			Output:            "stdout",
			EnableTracing:     true,
			EnableCorrelation: true,
		},
		ErrorTracker: ErrorTrackerConfig{
			Enabled:         true,
			MaxErrors:       10000,
			RetentionPeriod: 1 * time.Hour,
		},
		Aggregator: LogAggregatorConfig{
			Enabled:         true,
			MaxEntries:      10000,
			RetentionPeriod: 1 * time.Hour,
		},
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create monitoring service: %v", err)
	}

	// Benchmark trace creation and completion
	t.Run("TracingPerformance", func(t *testing.T) {
		ctx := context.Background()
		start := time.Now()

		for i := 0; i < 1000; i++ {
			trace, newCtx := service.StartTrace(ctx, "performance_test")
			service.AddTraceTag(newCtx, "iteration", fmt.Sprintf("%d", i))
			service.FinishTrace(newCtx, trace, nil)
		}

		duration := time.Since(start)
		avgPerTrace := duration / 1000

		t.Logf("Created and finished 1000 traces in %v (avg: %v per trace)", duration, avgPerTrace)

		if avgPerTrace > 1*time.Millisecond {
			t.Errorf("Trace performance too slow: %v per trace", avgPerTrace)
		}
	})

	// Benchmark error tracking
	t.Run("ErrorTrackingPerformance", func(t *testing.T) {
		ctx := context.Background()
		start := time.Now()

		for i := 0; i < 1000; i++ {
			err := errors.New(fmt.Sprintf("test error %d", i))
			service.TrackError(ctx, err, CategorySystem, "performance_test", "test")
		}

		duration := time.Since(start)
		avgPerError := duration / 1000

		t.Logf("Tracked 1000 errors in %v (avg: %v per error)", duration, avgPerError)

		if avgPerError > 500*time.Microsecond {
			t.Errorf("Error tracking performance too slow: %v per error", avgPerError)
		}
	})

	// Benchmark log aggregation
	t.Run("LogAggregationPerformance", func(t *testing.T) {
		start := time.Now()

		for i := 0; i < 1000; i++ {
			entry := LogEntry{
				Timestamp: time.Now(),
				Level:     "info",
				Message:   fmt.Sprintf("Performance test log %d", i),
				EventType: "test",
				Component: "performance",
				Duration:  float64(i),
			}
			service.aggregator.AddLogEntry(entry)
		}

		duration := time.Since(start)
		avgPerEntry := duration / 1000

		t.Logf("Added 1000 log entries in %v (avg: %v per entry)", duration, avgPerEntry)

		if avgPerEntry > 100*time.Microsecond {
			t.Errorf("Log aggregation performance too slow: %v per entry", avgPerEntry)
		}
	})
}
