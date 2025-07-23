package monitoring

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// ErrorCategory represents the category of an error
type ErrorCategory string

const (
	CategoryAuth       ErrorCategory = "authentication"
	CategoryDatabase   ErrorCategory = "database"
	CategoryCache      ErrorCategory = "cache"
	CategoryNetwork    ErrorCategory = "network"
	CategoryValidation ErrorCategory = "validation"
	CategorySecurity   ErrorCategory = "security"
	CategorySystem     ErrorCategory = "system"
	CategoryExternal   ErrorCategory = "external"
)

// ErrorEvent represents a tracked error event
type ErrorEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Error        error                  `json:"-"`
	ErrorMessage string                 `json:"error_message"`
	ErrorType    string                 `json:"error_type"`
	Category     ErrorCategory          `json:"category"`
	Severity     ErrorSeverity          `json:"severity"`
	Operation    string                 `json:"operation"`
	Component    string                 `json:"component"`
	UserID       string                 `json:"user_id,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	TraceID      string                 `json:"trace_id,omitempty"`
	StackTrace   string                 `json:"stack_trace,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	Count        int                    `json:"count"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	Resolved     bool                   `json:"resolved"`
	ResolvedAt   *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy   string                 `json:"resolved_by,omitempty"`
	Tags         map[string]string      `json:"tags,omitempty"`
}

// ErrorPattern represents a pattern for error grouping
type ErrorPattern struct {
	ID          string        `json:"id"`
	Pattern     string        `json:"pattern"`
	Category    ErrorCategory `json:"category"`
	Severity    ErrorSeverity `json:"severity"`
	Description string        `json:"description"`
	Count       int           `json:"count"`
	LastSeen    time.Time     `json:"last_seen"`
}

// AlertRule represents an alerting rule for errors
type AlertRule struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Category   ErrorCategory `json:"category"`
	Severity   ErrorSeverity `json:"severity"`
	Threshold  int           `json:"threshold"`
	TimeWindow time.Duration `json:"time_window"`
	Enabled    bool          `json:"enabled"`
	LastFired  *time.Time    `json:"last_fired,omitempty"`
	Cooldown   time.Duration `json:"cooldown"`
}

// Alert represents a fired alert
type Alert struct {
	ID         string                 `json:"id"`
	RuleID     string                 `json:"rule_id"`
	RuleName   string                 `json:"rule_name"`
	Timestamp  time.Time              `json:"timestamp"`
	Severity   ErrorSeverity          `json:"severity"`
	Message    string                 `json:"message"`
	ErrorCount int                    `json:"error_count"`
	TimeWindow time.Duration          `json:"time_window"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Resolved   bool                   `json:"resolved"`
	ResolvedAt *time.Time             `json:"resolved_at,omitempty"`
}

// ErrorTracker tracks and aggregates errors for alerting and analysis
type ErrorTracker struct {
	errors    map[string]*ErrorEvent
	patterns  map[string]*ErrorPattern
	rules     map[string]*AlertRule
	alerts    map[string]*Alert
	mu        sync.RWMutex
	logger    *Logger
	alertChan chan *Alert
}

// ErrorTrackerConfig contains configuration for error tracking
type ErrorTrackerConfig struct {
	Enabled          bool          `yaml:"enabled"`
	MaxErrors        int           `yaml:"max_errors"`
	RetentionPeriod  time.Duration `yaml:"retention_period"`
	AlertingEnabled  bool          `yaml:"alerting_enabled"`
	AlertBuffer      int           `yaml:"alert_buffer"`
	DefaultSeverity  ErrorSeverity `yaml:"default_severity"`
	EnableStackTrace bool          `yaml:"enable_stack_trace"`
	EnableGrouping   bool          `yaml:"enable_grouping"`
}

// NewErrorTracker creates a new error tracker
func NewErrorTracker(config ErrorTrackerConfig, logger *Logger) *ErrorTracker {
	tracker := &ErrorTracker{
		errors:    make(map[string]*ErrorEvent),
		patterns:  make(map[string]*ErrorPattern),
		rules:     make(map[string]*AlertRule),
		alerts:    make(map[string]*Alert),
		logger:    logger,
		alertChan: make(chan *Alert, config.AlertBuffer),
	}

	// Set up default alert rules
	tracker.setupDefaultRules()

	// Start background cleanup
	go tracker.cleanupRoutine(config.RetentionPeriod)

	return tracker
}

// TrackError tracks an error event
func (et *ErrorTracker) TrackError(ctx context.Context, err error, category ErrorCategory, operation, component string) string {
	if err == nil {
		return ""
	}

	et.mu.Lock()
	defer et.mu.Unlock()

	// Generate error ID based on error type and message for grouping
	errorID := et.generateErrorID(err, operation, component)

	// Get context information
	userID := getStringFromContext(ctx, "user_id")
	requestID := getStringFromContext(ctx, "request_id")
	traceID := getStringFromContext(ctx, "trace_id")

	now := time.Now()

	// Check if this error already exists
	if existingError, exists := et.errors[errorID]; exists {
		// Update existing error
		existingError.Count++
		existingError.LastSeen = now
		existingError.RequestID = requestID // Update with latest request
		existingError.TraceID = traceID     // Update with latest trace
	} else {
		// Create new error event
		severity := et.categorizeErrorSeverity(err, category)

		errorEvent := &ErrorEvent{
			ID:           errorID,
			Timestamp:    now,
			Error:        err,
			ErrorMessage: err.Error(),
			ErrorType:    fmt.Sprintf("%T", err),
			Category:     category,
			Severity:     severity,
			Operation:    operation,
			Component:    component,
			UserID:       userID,
			RequestID:    requestID,
			TraceID:      traceID,
			Context:      make(map[string]interface{}),
			Count:        1,
			FirstSeen:    now,
			LastSeen:     now,
			Resolved:     false,
			Tags:         make(map[string]string),
		}

		// Add stack trace if enabled
		if et.logger != nil && et.logger.level == LogLevelDebug {
			errorEvent.StackTrace = getStackTrace()
		}

		et.errors[errorID] = errorEvent
	}

	// Check alert rules
	et.checkAlertRules(category, et.errors[errorID].Severity)

	// Log the error
	if et.logger != nil {
		et.logger.ErrorEvent(ctx, err, operation, map[string]interface{}{
			"category":  category,
			"component": component,
			"error_id":  errorID,
			"count":     et.errors[errorID].Count,
		})
	}

	return errorID
}

// AddErrorContext adds context information to an error
func (et *ErrorTracker) AddErrorContext(errorID string, key string, value interface{}) {
	et.mu.Lock()
	defer et.mu.Unlock()

	if errorEvent, exists := et.errors[errorID]; exists {
		if errorEvent.Context == nil {
			errorEvent.Context = make(map[string]interface{})
		}
		errorEvent.Context[key] = value
	}
}

// AddErrorTag adds a tag to an error
func (et *ErrorTracker) AddErrorTag(errorID string, key, value string) {
	et.mu.Lock()
	defer et.mu.Unlock()

	if errorEvent, exists := et.errors[errorID]; exists {
		if errorEvent.Tags == nil {
			errorEvent.Tags = make(map[string]string)
		}
		errorEvent.Tags[key] = value
	}
}

// ResolveError marks an error as resolved
func (et *ErrorTracker) ResolveError(errorID, resolvedBy string) {
	et.mu.Lock()
	defer et.mu.Unlock()

	if errorEvent, exists := et.errors[errorID]; exists {
		now := time.Now()
		errorEvent.Resolved = true
		errorEvent.ResolvedAt = &now
		errorEvent.ResolvedBy = resolvedBy
	}
}

// GetError retrieves an error by ID
func (et *ErrorTracker) GetError(errorID string) (*ErrorEvent, bool) {
	et.mu.RLock()
	defer et.mu.RUnlock()

	errorEvent, exists := et.errors[errorID]
	return errorEvent, exists
}

// GetErrors retrieves all errors with optional filtering
func (et *ErrorTracker) GetErrors(category ErrorCategory, severity ErrorSeverity, resolved *bool) []*ErrorEvent {
	et.mu.RLock()
	defer et.mu.RUnlock()

	var result []*ErrorEvent
	for _, errorEvent := range et.errors {
		// Apply filters
		if category != "" && errorEvent.Category != category {
			continue
		}
		if severity != "" && errorEvent.Severity != severity {
			continue
		}
		if resolved != nil && errorEvent.Resolved != *resolved {
			continue
		}

		result = append(result, errorEvent)
	}

	return result
}

// AddAlertRule adds a new alert rule
func (et *ErrorTracker) AddAlertRule(rule *AlertRule) {
	et.mu.Lock()
	defer et.mu.Unlock()

	et.rules[rule.ID] = rule
}

// RemoveAlertRule removes an alert rule
func (et *ErrorTracker) RemoveAlertRule(ruleID string) {
	et.mu.Lock()
	defer et.mu.Unlock()

	delete(et.rules, ruleID)
}

// GetAlerts retrieves all alerts
func (et *ErrorTracker) GetAlerts(resolved *bool) []*Alert {
	et.mu.RLock()
	defer et.mu.RUnlock()

	var result []*Alert
	for _, alert := range et.alerts {
		if resolved != nil && alert.Resolved != *resolved {
			continue
		}
		result = append(result, alert)
	}

	return result
}

// GetAlertChannel returns the alert channel for external consumption
func (et *ErrorTracker) GetAlertChannel() <-chan *Alert {
	return et.alertChan
}

// generateErrorID generates a unique ID for error grouping
func (et *ErrorTracker) generateErrorID(err error, operation, component string) string {
	// Create a hash-like ID based on error type, message pattern, operation, and component
	errorType := fmt.Sprintf("%T", err)
	message := err.Error()

	// Normalize the message to group similar errors
	normalizedMessage := et.normalizeErrorMessage(message)

	return fmt.Sprintf("%s_%s_%s_%s", errorType, normalizedMessage, operation, component)
}

// normalizeErrorMessage normalizes error messages for grouping
func (et *ErrorTracker) normalizeErrorMessage(message string) string {
	// This is a simplified normalization - in production, you'd want more sophisticated pattern matching
	// Remove numbers, UUIDs, timestamps, etc.
	normalized := message

	// Remove common variable parts (this is a basic implementation)
	patterns := []string{
		`\d+`,               // Numbers
		`[a-f0-9-]{36}`,     // UUIDs
		`\d{4}-\d{2}-\d{2}`, // Dates
		`\d{2}:\d{2}:\d{2}`, // Times
	}

	for _, pattern := range patterns {
		// In a real implementation, you'd use regex
		// For simplicity, we'll just use the original message
		_ = pattern
	}

	return normalized
}

// categorizeErrorSeverity determines the severity of an error
func (et *ErrorTracker) categorizeErrorSeverity(err error, category ErrorCategory) ErrorSeverity {
	errorMsg := err.Error()

	// Critical errors
	if category == CategorySecurity {
		return SeverityCritical
	}

	// High severity errors
	if category == CategoryDatabase && (contains(errorMsg, "connection") ||
		contains(errorMsg, "timeout") ||
		contains(errorMsg, "deadlock")) {
		return SeverityHigh
	}

	if category == CategoryAuth && (contains(errorMsg, "unauthorized") ||
		contains(errorMsg, "forbidden")) {
		return SeverityMedium
	}

	// Medium severity errors
	if category == CategoryValidation {
		return SeverityMedium
	}

	// Default to low severity
	return SeverityLow
}

// checkAlertRules checks if any alert rules should be fired
func (et *ErrorTracker) checkAlertRules(category ErrorCategory, severity ErrorSeverity) {
	now := time.Now()

	for _, rule := range et.rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule matches the error
		if rule.Category != "" && rule.Category != category {
			continue
		}

		if rule.Severity != "" && rule.Severity != severity {
			continue
		}

		// Check cooldown
		if rule.LastFired != nil && now.Sub(*rule.LastFired) < rule.Cooldown {
			continue
		}

		// Count errors in time window
		errorCount := et.countErrorsInWindow(category, severity, rule.TimeWindow)

		if errorCount >= rule.Threshold {
			// Fire alert
			alert := &Alert{
				ID:         generateID(),
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Timestamp:  now,
				Severity:   severity,
				Message:    fmt.Sprintf("Error threshold exceeded: %d errors in %v", errorCount, rule.TimeWindow),
				ErrorCount: errorCount,
				TimeWindow: rule.TimeWindow,
				Context: map[string]interface{}{
					"category": category,
					"severity": severity,
				},
				Resolved: false,
			}

			et.alerts[alert.ID] = alert
			rule.LastFired = &now

			// Send alert to channel (non-blocking)
			select {
			case et.alertChan <- alert:
			default:
				// Channel is full, log warning
				if et.logger != nil {
					et.logger.Warn("Alert channel is full, dropping alert", "alert_id", alert.ID)
				}
			}
		}
	}
}

// countErrorsInWindow counts errors in a time window
func (et *ErrorTracker) countErrorsInWindow(category ErrorCategory, severity ErrorSeverity, window time.Duration) int {
	now := time.Now()
	cutoff := now.Add(-window)
	count := 0

	for _, errorEvent := range et.errors {
		if errorEvent.LastSeen.Before(cutoff) {
			continue
		}

		if category != "" && errorEvent.Category != category {
			continue
		}

		if severity != "" && errorEvent.Severity != severity {
			continue
		}

		count += errorEvent.Count
	}

	return count
}

// setupDefaultRules sets up default alert rules
func (et *ErrorTracker) setupDefaultRules() {
	defaultRules := []*AlertRule{
		{
			ID:         "critical_errors",
			Name:       "Critical Errors",
			Category:   "",
			Severity:   SeverityCritical,
			Threshold:  1,
			TimeWindow: 5 * time.Minute,
			Enabled:    true,
			Cooldown:   15 * time.Minute,
		},
		{
			ID:         "high_error_rate",
			Name:       "High Error Rate",
			Category:   "",
			Severity:   SeverityHigh,
			Threshold:  10,
			TimeWindow: 10 * time.Minute,
			Enabled:    true,
			Cooldown:   30 * time.Minute,
		},
		{
			ID:         "auth_failures",
			Name:       "Authentication Failures",
			Category:   CategoryAuth,
			Severity:   "",
			Threshold:  20,
			TimeWindow: 5 * time.Minute,
			Enabled:    true,
			Cooldown:   10 * time.Minute,
		},
		{
			ID:         "database_errors",
			Name:       "Database Errors",
			Category:   CategoryDatabase,
			Severity:   "",
			Threshold:  5,
			TimeWindow: 5 * time.Minute,
			Enabled:    true,
			Cooldown:   15 * time.Minute,
		},
	}

	for _, rule := range defaultRules {
		et.rules[rule.ID] = rule
	}
}

// cleanupRoutine periodically cleans up old errors
func (et *ErrorTracker) cleanupRoutine(retentionPeriod time.Duration) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		et.cleanup(retentionPeriod)
	}
}

// cleanup removes old errors and alerts
func (et *ErrorTracker) cleanup(retentionPeriod time.Duration) {
	et.mu.Lock()
	defer et.mu.Unlock()

	cutoff := time.Now().Add(-retentionPeriod)

	// Clean up old errors
	for id, errorEvent := range et.errors {
		if errorEvent.LastSeen.Before(cutoff) {
			delete(et.errors, id)
		}
	}

	// Clean up old alerts
	for id, alert := range et.alerts {
		if alert.Timestamp.Before(cutoff) {
			delete(et.alerts, id)
		}
	}
}

// Helper functions
func getStringFromContext(ctx context.Context, key string) string {
	if value := ctx.Value(key); value != nil {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			strings.Contains(s, substr))))
}
