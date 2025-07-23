package monitoring

import (
	"fmt"
	"testing"
	"time"
)

func TestNewLogAggregator(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:           true,
		MaxEntries:        1000,
		RetentionPeriod:   24 * time.Hour,
		AggregationLevels: []string{"minute", "hour"},
		PatternDetection:  true,
		MetricsEnabled:    true,
	}

	logger, err := NewLogger(LoggerConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	aggregator := NewLogAggregator(config, logger)

	if aggregator == nil {
		t.Error("NewLogAggregator() returned nil")
	}

	if aggregator.maxEntries != config.MaxEntries {
		t.Errorf("Expected maxEntries %d, got %d", config.MaxEntries, aggregator.maxEntries)
	}

	if aggregator.retention != config.RetentionPeriod {
		t.Errorf("Expected retention %v, got %v", config.RetentionPeriod, aggregator.retention)
	}
}

func TestLogAggregator_AddLogEntry(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:         true,
		MaxEntries:      10,
		RetentionPeriod: 24 * time.Hour,
	}

	aggregator := NewLogAggregator(config, nil)

	entry := LogEntry{
		Timestamp:     time.Now(),
		Level:         "info",
		Message:       "test message",
		EventType:     "http",
		Component:     "api",
		Operation:     "GET /users",
		Duration:      100.5,
		UserID:        "user-123",
		RequestID:     "req-456",
		TraceID:       "trace-789",
		CorrelationID: "corr-abc",
		ClientIP:      "192.168.1.1",
		UserAgent:     "test-agent",
		StatusCode:    200,
		Fields: map[string]interface{}{
			"method": "GET",
			"path":   "/users",
		},
	}

	aggregator.AddLogEntry(entry)

	aggregator.mu.RLock()
	entriesCount := len(aggregator.entries)
	aggregator.mu.RUnlock()

	if entriesCount != 1 {
		t.Errorf("Expected 1 entry, got %d", entriesCount)
	}

	// Test buffer size limit
	for i := 0; i < 15; i++ {
		entry.Timestamp = time.Now().Add(time.Duration(i) * time.Second)
		entry.Message = fmt.Sprintf("test message %d", i)
		aggregator.AddLogEntry(entry)
	}

	aggregator.mu.RLock()
	finalCount := len(aggregator.entries)
	aggregator.mu.RUnlock()

	if finalCount > config.MaxEntries {
		t.Errorf("Expected entries count to not exceed %d, got %d", config.MaxEntries, finalCount)
	}
}

func TestLogAggregator_SearchLogs(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:         true,
		MaxEntries:      1000,
		RetentionPeriod: 24 * time.Hour,
	}

	aggregator := NewLogAggregator(config, nil)

	// Add test entries
	entries := []LogEntry{
		{
			Timestamp: time.Now().Add(-1 * time.Hour),
			Level:     "info",
			Message:   "user login",
			EventType: "auth",
			Component: "auth-service",
			Operation: "login",
			UserID:    "user-123",
			RequestID: "req-1",
			TraceID:   "trace-1",
		},
		{
			Timestamp: time.Now().Add(-30 * time.Minute),
			Level:     "error",
			Message:   "database connection failed",
			EventType: "database",
			Component: "postgres",
			Operation: "connect",
			Error:     "connection timeout",
			RequestID: "req-2",
			TraceID:   "trace-2",
		},
		{
			Timestamp: time.Now().Add(-10 * time.Minute),
			Level:     "warn",
			Message:   "slow query detected",
			EventType: "database",
			Component: "postgres",
			Operation: "query",
			UserID:    "user-456",
			RequestID: "req-3",
			TraceID:   "trace-3",
		},
	}

	for _, entry := range entries {
		aggregator.AddLogEntry(entry)
	}

	// Test search by level
	query := LogSearchQuery{Level: "error"}
	results := aggregator.SearchLogs(query)
	if len(results) != 1 {
		t.Errorf("Expected 1 error log, got %d", len(results))
	}

	// Test search by event type
	query = LogSearchQuery{EventType: "database"}
	results = aggregator.SearchLogs(query)
	if len(results) != 2 {
		t.Errorf("Expected 2 database logs, got %d", len(results))
	}

	// Test search by component
	query = LogSearchQuery{Component: "postgres"}
	results = aggregator.SearchLogs(query)
	if len(results) != 2 {
		t.Errorf("Expected 2 postgres logs, got %d", len(results))
	}

	// Test search by user ID
	query = LogSearchQuery{UserID: "user-123"}
	results = aggregator.SearchLogs(query)
	if len(results) != 1 {
		t.Errorf("Expected 1 log for user-123, got %d", len(results))
	}

	// Test search by message content
	query = LogSearchQuery{Message: "login"}
	results = aggregator.SearchLogs(query)
	if len(results) != 1 {
		t.Errorf("Expected 1 log containing 'login', got %d", len(results))
	}

	// Test search by error content
	query = LogSearchQuery{Error: "timeout"}
	results = aggregator.SearchLogs(query)
	if len(results) != 1 {
		t.Errorf("Expected 1 log containing 'timeout' in error, got %d", len(results))
	}

	// Test search with time range
	start := time.Now().Add(-45 * time.Minute)
	end := time.Now().Add(-15 * time.Minute)
	query = LogSearchQuery{Start: start, End: end}
	results = aggregator.SearchLogs(query)
	if len(results) != 1 {
		t.Errorf("Expected 1 log in time range, got %d", len(results))
	}

	// Test search with limit
	query = LogSearchQuery{Limit: 2}
	results = aggregator.SearchLogs(query)
	if len(results) != 2 {
		t.Errorf("Expected 2 logs with limit, got %d", len(results))
	}
}

func TestLogAggregator_GetLogStatistics(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:         true,
		MaxEntries:      1000,
		RetentionPeriod: 24 * time.Hour,
	}

	aggregator := NewLogAggregator(config, nil)

	// Add test entries with different levels and durations
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
		{
			Timestamp: time.Now(),
			Level:     "warn",
			EventType: "cache",
			Component: "redis",
			Duration:  50.0,
		},
		{
			Timestamp: time.Now(),
			Level:     "info",
			EventType: "http",
			Component: "api",
			Duration:  150.0,
		},
	}

	for _, entry := range entries {
		aggregator.AddLogEntry(entry)
	}

	stats := aggregator.GetLogStatistics(time.Time{}, time.Time{})

	if stats.TotalEntries != 4 {
		t.Errorf("Expected 4 total entries, got %d", stats.TotalEntries)
	}

	if stats.LevelCounts["info"] != 2 {
		t.Errorf("Expected 2 info logs, got %d", stats.LevelCounts["info"])
	}

	if stats.LevelCounts["error"] != 1 {
		t.Errorf("Expected 1 error log, got %d", stats.LevelCounts["error"])
	}

	if stats.LevelCounts["warn"] != 1 {
		t.Errorf("Expected 1 warn log, got %d", stats.LevelCounts["warn"])
	}

	if stats.EventCounts["http"] != 2 {
		t.Errorf("Expected 2 http events, got %d", stats.EventCounts["http"])
	}

	if stats.ComponentCounts["api"] != 2 {
		t.Errorf("Expected 2 api components, got %d", stats.ComponentCounts["api"])
	}

	// Error rate should be 25% (1 error out of 4 entries)
	expectedErrorRate := 25.0
	if stats.ErrorRate != expectedErrorRate {
		t.Errorf("Expected error rate %.1f%%, got %.1f%%", expectedErrorRate, stats.ErrorRate)
	}

	// Average duration should be (100 + 200 + 50 + 150) / 4 = 125
	expectedAvgDuration := 125.0
	if stats.AvgDuration != expectedAvgDuration {
		t.Errorf("Expected average duration %.1f, got %.1f", expectedAvgDuration, stats.AvgDuration)
	}
}

func TestLogAggregator_GetMetrics(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:         true,
		MaxEntries:      1000,
		RetentionPeriod: 24 * time.Hour,
	}

	aggregator := NewLogAggregator(config, nil)

	// Add test entries
	now := time.Now()
	entries := []LogEntry{
		{
			Timestamp: now.Truncate(time.Minute),
			Level:     "info",
			EventType: "http",
			Component: "api",
			Operation: "GET /users",
			Duration:  100.0,
		},
		{
			Timestamp: now.Truncate(time.Minute),
			Level:     "error",
			EventType: "http",
			Component: "api",
			Operation: "GET /users",
			Duration:  200.0,
		},
	}

	for _, entry := range entries {
		aggregator.AddLogEntry(entry)
	}

	// Manually trigger processing to create metrics
	aggregator.processEntries()

	// Get metrics
	metrics := aggregator.GetMetrics("http", "api", AggregationMinute, time.Time{}, time.Time{})

	if len(metrics) == 0 {
		t.Error("Expected metrics to be generated")
	}

	// Test filtering
	filteredMetrics := aggregator.GetMetrics("database", "", AggregationMinute, time.Time{}, time.Time{})
	if len(filteredMetrics) != 0 {
		t.Errorf("Expected 0 database metrics, got %d", len(filteredMetrics))
	}
}

func TestLogAggregator_GetPatterns(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:          true,
		MaxEntries:       1000,
		RetentionPeriod:  24 * time.Hour,
		PatternDetection: true,
	}

	aggregator := NewLogAggregator(config, nil)

	// Add multiple similar entries to create a pattern
	eventType := "http"
	component := "api"
	for i := 0; i < 10; i++ {
		entry := LogEntry{
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			Level:     "info",
			EventType: eventType,
			Component: component,
			Operation: "GET /users",
			Duration:  float64(100 + i),
		}
		aggregator.AddLogEntry(entry)
	}

	// Manually trigger processing to detect patterns
	aggregator.processEntries()

	// Get patterns
	patterns := aggregator.GetPatterns(eventType, component)

	if len(patterns) == 0 {
		t.Error("Expected patterns to be detected")
	}

	// Test filtering
	filteredPatterns := aggregator.GetPatterns("database", "")
	if len(filteredPatterns) != 0 {
		t.Errorf("Expected 0 database patterns, got %d", len(filteredPatterns))
	}
}

func TestLogAggregator_ExportMetrics(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:         true,
		MaxEntries:      1000,
		RetentionPeriod: 24 * time.Hour,
	}

	aggregator := NewLogAggregator(config, nil)

	// Add a test metric manually
	metric := &LogMetric{
		Timestamp:   time.Now(),
		Level:       AggregationMinute,
		EventType:   "http",
		Component:   "api",
		Operation:   "GET /users",
		Count:       10,
		ErrorCount:  1,
		InfoCount:   9,
		AvgDuration: 150.0,
	}

	aggregator.mu.Lock()
	aggregator.metrics["test_metric"] = metric
	aggregator.mu.Unlock()

	// Test JSON export
	data, err := aggregator.ExportMetrics("json")
	if err != nil {
		t.Errorf("ExportMetrics() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected exported data to not be empty")
	}

	// Test unsupported format
	_, err = aggregator.ExportMetrics("xml")
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestPercentile(t *testing.T) {
	tests := []struct {
		name     string
		values   []float64
		p        float64
		expected float64
	}{
		{
			name:     "empty slice",
			values:   []float64{},
			p:        0.5,
			expected: 0,
		},
		{
			name:     "single value",
			values:   []float64{100},
			p:        0.5,
			expected: 100,
		},
		{
			name:     "median of odd count",
			values:   []float64{1, 2, 3, 4, 5},
			p:        0.5,
			expected: 3,
		},
		{
			name:     "95th percentile",
			values:   []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			p:        0.95,
			expected: 9.5,
		},
		{
			name:     "99th percentile",
			values:   []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			p:        0.99,
			expected: 9.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := percentile(tt.values, tt.p)
			if result != tt.expected {
				t.Errorf("percentile() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestLogAggregator_CreateMetricFromEntries(t *testing.T) {
	config := LogAggregatorConfig{
		Enabled:         true,
		MaxEntries:      1000,
		RetentionPeriod: 24 * time.Hour,
	}

	aggregator := NewLogAggregator(config, nil)

	now := time.Now()
	entries := []LogEntry{
		{
			Timestamp: now,
			Level:     "info",
			EventType: "http",
			Component: "api",
			Operation: "GET /users",
			Duration:  100.0,
		},
		{
			Timestamp: now,
			Level:     "error",
			EventType: "http",
			Component: "api",
			Operation: "GET /users",
			Duration:  200.0,
		},
		{
			Timestamp: now,
			Level:     "warn",
			EventType: "http",
			Component: "api",
			Operation: "GET /users",
			Duration:  150.0,
		},
	}

	key := "minute_http_api_GET /users_" + fmt.Sprintf("%d", now.Truncate(time.Minute).Unix())
	metric := aggregator.createMetricFromEntries(key, entries)

	if metric == nil {
		t.Error("createMetricFromEntries() returned nil")
	}

	if metric.Count != 3 {
		t.Errorf("Expected count 3, got %d", metric.Count)
	}

	if metric.ErrorCount != 1 {
		t.Errorf("Expected error count 1, got %d", metric.ErrorCount)
	}

	if metric.WarnCount != 1 {
		t.Errorf("Expected warn count 1, got %d", metric.WarnCount)
	}

	if metric.InfoCount != 1 {
		t.Errorf("Expected info count 1, got %d", metric.InfoCount)
	}

	if metric.Level != AggregationMinute {
		t.Errorf("Expected aggregation level minute, got %s", metric.Level)
	}

	expectedAvg := (100.0 + 200.0 + 150.0) / 3.0
	if metric.AvgDuration != expectedAvg {
		t.Errorf("Expected average duration %.1f, got %.1f", expectedAvg, metric.AvgDuration)
	}

	if metric.MinDuration != 100.0 {
		t.Errorf("Expected min duration 100.0, got %.1f", metric.MinDuration)
	}

	if metric.MaxDuration != 200.0 {
		t.Errorf("Expected max duration 200.0, got %.1f", metric.MaxDuration)
	}
}
