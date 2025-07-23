package monitoring

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// LogLevel represents log levels for aggregation
type AggregationLevel string

const (
	AggregationMinute AggregationLevel = "minute"
	AggregationHour   AggregationLevel = "hour"
	AggregationDay    AggregationLevel = "day"
)

// LogMetric represents aggregated log metrics
type LogMetric struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       AggregationLevel       `json:"level"`
	EventType   string                 `json:"event_type"`
	Component   string                 `json:"component"`
	Operation   string                 `json:"operation"`
	Count       int64                  `json:"count"`
	ErrorCount  int64                  `json:"error_count"`
	WarnCount   int64                  `json:"warn_count"`
	InfoCount   int64                  `json:"info_count"`
	DebugCount  int64                  `json:"debug_count"`
	AvgDuration float64                `json:"avg_duration_ms"`
	MinDuration float64                `json:"min_duration_ms"`
	MaxDuration float64                `json:"max_duration_ms"`
	P50Duration float64                `json:"p50_duration_ms"`
	P95Duration float64                `json:"p95_duration_ms"`
	P99Duration float64                `json:"p99_duration_ms"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LogEntry represents a structured log entry for aggregation
type LogEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	EventType     string                 `json:"event_type"`
	Component     string                 `json:"component"`
	Operation     string                 `json:"operation"`
	Duration      float64                `json:"duration_ms,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	ClientIP      string                 `json:"client_ip,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	StatusCode    int                    `json:"status_code,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
	Source        string                 `json:"source,omitempty"`
}

// LogPattern represents a detected log pattern
type LogPattern struct {
	ID        string                 `json:"id"`
	Pattern   string                 `json:"pattern"`
	EventType string                 `json:"event_type"`
	Component string                 `json:"component"`
	Count     int64                  `json:"count"`
	FirstSeen time.Time              `json:"first_seen"`
	LastSeen  time.Time              `json:"last_seen"`
	Frequency float64                `json:"frequency"` // events per minute
	Severity  string                 `json:"severity"`
	Examples  []LogEntry             `json:"examples,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// LogAggregator aggregates and analyzes log data
type LogAggregator struct {
	metrics    map[string]*LogMetric
	patterns   map[string]*LogPattern
	entries    []LogEntry
	mu         sync.RWMutex
	maxEntries int
	retention  time.Duration
	logger     *Logger
}

// LogAggregatorConfig contains configuration for log aggregation
type LogAggregatorConfig struct {
	Enabled           bool          `yaml:"enabled"`
	MaxEntries        int           `yaml:"max_entries"`
	RetentionPeriod   time.Duration `yaml:"retention_period"`
	AggregationLevels []string      `yaml:"aggregation_levels"`
	PatternDetection  bool          `yaml:"pattern_detection"`
	MetricsEnabled    bool          `yaml:"metrics_enabled"`
}

// NewLogAggregator creates a new log aggregator
func NewLogAggregator(config LogAggregatorConfig, logger *Logger) *LogAggregator {
	aggregator := &LogAggregator{
		metrics:    make(map[string]*LogMetric),
		patterns:   make(map[string]*LogPattern),
		entries:    make([]LogEntry, 0, config.MaxEntries),
		maxEntries: config.MaxEntries,
		retention:  config.RetentionPeriod,
		logger:     logger,
	}

	// Start background processing
	go aggregator.processRoutine()
	go aggregator.cleanupRoutine()

	return aggregator
}

// AddLogEntry adds a log entry for aggregation
func (la *LogAggregator) AddLogEntry(entry LogEntry) {
	la.mu.Lock()
	defer la.mu.Unlock()

	// Add to entries buffer
	la.entries = append(la.entries, entry)

	// Maintain buffer size
	if len(la.entries) > la.maxEntries {
		// Remove oldest entries
		copy(la.entries, la.entries[len(la.entries)-la.maxEntries:])
		la.entries = la.entries[:la.maxEntries]
	}
}

// GetMetrics retrieves aggregated metrics
func (la *LogAggregator) GetMetrics(eventType, component string, level AggregationLevel, start, end time.Time) []*LogMetric {
	la.mu.RLock()
	defer la.mu.RUnlock()

	var result []*LogMetric
	for _, metric := range la.metrics {
		// Apply filters
		if eventType != "" && metric.EventType != eventType {
			continue
		}
		if component != "" && metric.Component != component {
			continue
		}
		if level != "" && metric.Level != level {
			continue
		}
		if !start.IsZero() && metric.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && metric.Timestamp.After(end) {
			continue
		}

		result = append(result, metric)
	}

	// Sort by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.Before(result[j].Timestamp)
	})

	return result
}

// GetPatterns retrieves detected log patterns
func (la *LogAggregator) GetPatterns(eventType, component string) []*LogPattern {
	la.mu.RLock()
	defer la.mu.RUnlock()

	var result []*LogPattern
	for _, pattern := range la.patterns {
		// Apply filters
		if eventType != "" && pattern.EventType != eventType {
			continue
		}
		if component != "" && pattern.Component != component {
			continue
		}

		result = append(result, pattern)
	}

	// Sort by frequency (descending)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Frequency > result[j].Frequency
	})

	return result
}

// SearchLogs searches log entries with filters
func (la *LogAggregator) SearchLogs(query LogSearchQuery) []*LogEntry {
	la.mu.RLock()
	defer la.mu.RUnlock()

	var result []*LogEntry
	for i := range la.entries {
		entry := &la.entries[i]

		// Apply filters
		if !query.Start.IsZero() && entry.Timestamp.Before(query.Start) {
			continue
		}
		if !query.End.IsZero() && entry.Timestamp.After(query.End) {
			continue
		}
		if query.Level != "" && entry.Level != query.Level {
			continue
		}
		if query.EventType != "" && entry.EventType != query.EventType {
			continue
		}
		if query.Component != "" && entry.Component != query.Component {
			continue
		}
		if query.Operation != "" && entry.Operation != query.Operation {
			continue
		}
		if query.UserID != "" && entry.UserID != query.UserID {
			continue
		}
		if query.RequestID != "" && entry.RequestID != query.RequestID {
			continue
		}
		if query.TraceID != "" && entry.TraceID != query.TraceID {
			continue
		}
		if query.Message != "" && !contains(entry.Message, query.Message) {
			continue
		}
		if query.Error != "" && !contains(entry.Error, query.Error) {
			continue
		}

		result = append(result, entry)
	}

	// Sort by timestamp (descending - newest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.After(result[j].Timestamp)
	})

	// Apply limit
	if query.Limit > 0 && len(result) > query.Limit {
		result = result[:query.Limit]
	}

	return result
}

// LogSearchQuery represents a log search query
type LogSearchQuery struct {
	Start     time.Time `json:"start,omitempty"`
	End       time.Time `json:"end,omitempty"`
	Level     string    `json:"level,omitempty"`
	EventType string    `json:"event_type,omitempty"`
	Component string    `json:"component,omitempty"`
	Operation string    `json:"operation,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	Message   string    `json:"message,omitempty"`
	Error     string    `json:"error,omitempty"`
	Limit     int       `json:"limit,omitempty"`
}

// GetLogStatistics returns statistics about log data
func (la *LogAggregator) GetLogStatistics(start, end time.Time) *LogStatistics {
	la.mu.RLock()
	defer la.mu.RUnlock()

	stats := &LogStatistics{
		TotalEntries:    int64(len(la.entries)),
		LevelCounts:     make(map[string]int64),
		EventCounts:     make(map[string]int64),
		ComponentCounts: make(map[string]int64),
		ErrorRate:       0,
		AvgDuration:     0,
	}

	var totalDuration float64
	var durationCount int64
	var errorCount int64

	for _, entry := range la.entries {
		// Apply time filter
		if !start.IsZero() && entry.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && entry.Timestamp.After(end) {
			continue
		}

		// Count by level
		stats.LevelCounts[entry.Level]++

		// Count by event type
		stats.EventCounts[entry.EventType]++

		// Count by component
		stats.ComponentCounts[entry.Component]++

		// Track errors
		if entry.Level == "error" || entry.Error != "" {
			errorCount++
		}

		// Track duration
		if entry.Duration > 0 {
			totalDuration += entry.Duration
			durationCount++
		}
	}

	// Calculate error rate
	if stats.TotalEntries > 0 {
		stats.ErrorRate = float64(errorCount) / float64(stats.TotalEntries) * 100
	}

	// Calculate average duration
	if durationCount > 0 {
		stats.AvgDuration = totalDuration / float64(durationCount)
	}

	return stats
}

// LogStatistics represents log statistics
type LogStatistics struct {
	TotalEntries    int64            `json:"total_entries"`
	LevelCounts     map[string]int64 `json:"level_counts"`
	EventCounts     map[string]int64 `json:"event_counts"`
	ComponentCounts map[string]int64 `json:"component_counts"`
	ErrorRate       float64          `json:"error_rate_percent"`
	AvgDuration     float64          `json:"avg_duration_ms"`
}

// processRoutine processes log entries in the background
func (la *LogAggregator) processRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		la.processEntries()
	}
}

// processEntries processes accumulated log entries
func (la *LogAggregator) processEntries() {
	la.mu.Lock()
	defer la.mu.Unlock()

	if len(la.entries) == 0 {
		return
	}

	// Aggregate metrics
	la.aggregateMetrics()

	// Detect patterns
	la.detectPatterns()
}

// aggregateMetrics aggregates log entries into metrics
func (la *LogAggregator) aggregateMetrics() {
	// Group entries by time windows and other dimensions
	groups := make(map[string][]LogEntry)

	for _, entry := range la.entries {
		// Create different aggregation keys
		minuteKey := fmt.Sprintf("minute_%s_%s_%s_%d",
			entry.EventType, entry.Component, entry.Operation,
			entry.Timestamp.Truncate(time.Minute).Unix())

		hourKey := fmt.Sprintf("hour_%s_%s_%s_%d",
			entry.EventType, entry.Component, entry.Operation,
			entry.Timestamp.Truncate(time.Hour).Unix())

		groups[minuteKey] = append(groups[minuteKey], entry)
		groups[hourKey] = append(groups[hourKey], entry)
	}

	// Create metrics from groups
	for key, entries := range groups {
		if len(entries) == 0 {
			continue
		}

		metric := la.createMetricFromEntries(key, entries)
		la.metrics[key] = metric
	}
}

// createMetricFromEntries creates a metric from a group of log entries
func (la *LogAggregator) createMetricFromEntries(key string, entries []LogEntry) *LogMetric {
	if len(entries) == 0 {
		return nil
	}

	first := entries[0]
	metric := &LogMetric{
		EventType: first.EventType,
		Component: first.Component,
		Operation: first.Operation,
		Count:     int64(len(entries)),
		Metadata:  make(map[string]interface{}),
	}

	// Determine aggregation level and timestamp from key
	if contains(key, "minute_") {
		metric.Level = AggregationMinute
		metric.Timestamp = first.Timestamp.Truncate(time.Minute)
	} else if contains(key, "hour_") {
		metric.Level = AggregationHour
		metric.Timestamp = first.Timestamp.Truncate(time.Hour)
	}

	// Count by log level
	var durations []float64
	var totalDuration float64

	for _, entry := range entries {
		switch entry.Level {
		case "error":
			metric.ErrorCount++
		case "warn":
			metric.WarnCount++
		case "info":
			metric.InfoCount++
		case "debug":
			metric.DebugCount++
		}

		if entry.Duration > 0 {
			durations = append(durations, entry.Duration)
			totalDuration += entry.Duration
		}
	}

	// Calculate duration statistics
	if len(durations) > 0 {
		sort.Float64s(durations)

		metric.AvgDuration = totalDuration / float64(len(durations))
		metric.MinDuration = durations[0]
		metric.MaxDuration = durations[len(durations)-1]

		// Calculate percentiles
		metric.P50Duration = percentile(durations, 0.5)
		metric.P95Duration = percentile(durations, 0.95)
		metric.P99Duration = percentile(durations, 0.99)
	}

	return metric
}

// detectPatterns detects patterns in log entries
func (la *LogAggregator) detectPatterns() {
	// Group entries by event type and component
	groups := make(map[string][]LogEntry)

	for _, entry := range la.entries {
		key := fmt.Sprintf("%s_%s", entry.EventType, entry.Component)
		groups[key] = append(groups[key], entry)
	}

	// Analyze each group for patterns
	for key, entries := range groups {
		if len(entries) < 5 { // Need minimum entries to detect patterns
			continue
		}

		pattern := la.analyzePattern(key, entries)
		if pattern != nil {
			la.patterns[pattern.ID] = pattern
		}
	}
}

// analyzePattern analyzes a group of entries for patterns
func (la *LogAggregator) analyzePattern(key string, entries []LogEntry) *LogPattern {
	if len(entries) == 0 {
		return nil
	}

	first := entries[0]
	last := entries[len(entries)-1]

	pattern := &LogPattern{
		ID:        generateID(),
		Pattern:   key,
		EventType: first.EventType,
		Component: first.Component,
		Count:     int64(len(entries)),
		FirstSeen: first.Timestamp,
		LastSeen:  last.Timestamp,
		Examples:  make([]LogEntry, 0, 3),
		Metadata:  make(map[string]interface{}),
	}

	// Calculate frequency (events per minute)
	duration := last.Timestamp.Sub(first.Timestamp)
	if duration > 0 {
		pattern.Frequency = float64(len(entries)) / duration.Minutes()
	}

	// Determine severity based on log levels
	errorCount := 0
	warnCount := 0
	for _, entry := range entries {
		if entry.Level == "error" {
			errorCount++
		} else if entry.Level == "warn" {
			warnCount++
		}
	}

	if errorCount > len(entries)/2 {
		pattern.Severity = "high"
	} else if warnCount > len(entries)/2 {
		pattern.Severity = "medium"
	} else {
		pattern.Severity = "low"
	}

	// Add examples (first, middle, last)
	pattern.Examples = append(pattern.Examples, entries[0])
	if len(entries) > 2 {
		pattern.Examples = append(pattern.Examples, entries[len(entries)/2])
	}
	if len(entries) > 1 {
		pattern.Examples = append(pattern.Examples, entries[len(entries)-1])
	}

	return pattern
}

// cleanupRoutine periodically cleans up old data
func (la *LogAggregator) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		la.cleanup()
	}
}

// cleanup removes old data
func (la *LogAggregator) cleanup() {
	la.mu.Lock()
	defer la.mu.Unlock()

	cutoff := time.Now().Add(-la.retention)

	// Clean up old entries
	var newEntries []LogEntry
	for _, entry := range la.entries {
		if entry.Timestamp.After(cutoff) {
			newEntries = append(newEntries, entry)
		}
	}
	la.entries = newEntries

	// Clean up old metrics
	for key, metric := range la.metrics {
		if metric.Timestamp.Before(cutoff) {
			delete(la.metrics, key)
		}
	}

	// Clean up old patterns
	for key, pattern := range la.patterns {
		if pattern.LastSeen.Before(cutoff) {
			delete(la.patterns, key)
		}
	}
}

// ExportMetrics exports metrics in a specific format
func (la *LogAggregator) ExportMetrics(format string) ([]byte, error) {
	la.mu.RLock()
	defer la.mu.RUnlock()

	switch format {
	case "json":
		return json.Marshal(la.metrics)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// Helper function to calculate percentiles
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}

	index := p * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1

	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	weight := index - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}
