package monitoring

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewErrorTracker(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:          true,
		MaxErrors:        1000,
		RetentionPeriod:  24 * time.Hour,
		AlertingEnabled:  true,
		AlertBuffer:      100,
		DefaultSeverity:  SeverityMedium,
		EnableStackTrace: true,
		EnableGrouping:   true,
	}

	logger, err := NewLogger(LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	tracker := NewErrorTracker(config, logger)

	if tracker == nil {
		t.Error("NewErrorTracker() returned nil")
	}

	if len(tracker.rules) == 0 {
		t.Error("Expected default rules to be set up")
	}
}

func TestErrorTracker_TrackError(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:          true,
		MaxErrors:        1000,
		RetentionPeriod:  24 * time.Hour,
		AlertingEnabled:  true,
		AlertBuffer:      100,
		DefaultSeverity:  SeverityMedium,
		EnableStackTrace: false,
		EnableGrouping:   true,
	}

	logger, err := NewLogger(LoggerConfig{
		Level:  LogLevelDebug,
		Format: LogFormatJSON,
		Output: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	tracker := NewErrorTracker(config, logger)

	ctx := context.WithValue(context.Background(), "user_id", "user-123")
	ctx = context.WithValue(ctx, "request_id", "req-456")
	ctx = context.WithValue(ctx, "trace_id", "trace-789")

	testErr := errors.New("test error")
	category := CategoryDatabase
	operation := "SELECT"
	component := "postgres"

	errorID := tracker.TrackError(ctx, testErr, category, operation, component)

	if errorID == "" {
		t.Error("TrackError() returned empty error ID")
	}

	// Verify error was stored
	errorEvent, exists := tracker.GetError(errorID)
	if !exists {
		t.Error("Error was not stored")
	}

	if errorEvent.ErrorMessage != testErr.Error() {
		t.Errorf("Expected error message %s, got %s", testErr.Error(), errorEvent.ErrorMessage)
	}

	if errorEvent.Category != category {
		t.Errorf("Expected category %s, got %s", category, errorEvent.Category)
	}

	if errorEvent.Operation != operation {
		t.Errorf("Expected operation %s, got %s", operation, errorEvent.Operation)
	}

	if errorEvent.Component != component {
		t.Errorf("Expected component %s, got %s", component, errorEvent.Component)
	}

	if errorEvent.UserID != "user-123" {
		t.Errorf("Expected user ID user-123, got %s", errorEvent.UserID)
	}

	if errorEvent.Count != 1 {
		t.Errorf("Expected count 1, got %d", errorEvent.Count)
	}

	// Track the same error again to test grouping
	errorID2 := tracker.TrackError(ctx, testErr, category, operation, component)

	if errorID2 != errorID {
		t.Error("Same error should have the same ID")
	}

	errorEvent2, _ := tracker.GetError(errorID)
	if errorEvent2.Count != 2 {
		t.Errorf("Expected count 2, got %d", errorEvent2.Count)
	}
}

func TestErrorTracker_AddErrorContext(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: false,
	}

	tracker := NewErrorTracker(config, nil)

	ctx := context.Background()
	testErr := errors.New("test error")
	errorID := tracker.TrackError(ctx, testErr, CategorySystem, "test", "test")

	key := "additional_info"
	value := "test value"
	tracker.AddErrorContext(errorID, key, value)

	errorEvent, exists := tracker.GetError(errorID)
	if !exists {
		t.Error("Error not found")
	}

	if errorEvent.Context[key] != value {
		t.Errorf("Expected context value %s, got %v", value, errorEvent.Context[key])
	}
}

func TestErrorTracker_AddErrorTag(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: false,
	}

	tracker := NewErrorTracker(config, nil)

	ctx := context.Background()
	testErr := errors.New("test error")
	errorID := tracker.TrackError(ctx, testErr, CategorySystem, "test", "test")

	key := "environment"
	value := "production"
	tracker.AddErrorTag(errorID, key, value)

	errorEvent, exists := tracker.GetError(errorID)
	if !exists {
		t.Error("Error not found")
	}

	if errorEvent.Tags[key] != value {
		t.Errorf("Expected tag value %s, got %s", value, errorEvent.Tags[key])
	}
}

func TestErrorTracker_ResolveError(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: false,
	}

	tracker := NewErrorTracker(config, nil)

	ctx := context.Background()
	testErr := errors.New("test error")
	errorID := tracker.TrackError(ctx, testErr, CategorySystem, "test", "test")

	resolvedBy := "admin-123"
	tracker.ResolveError(errorID, resolvedBy)

	errorEvent, exists := tracker.GetError(errorID)
	if !exists {
		t.Error("Error not found")
	}

	if !errorEvent.Resolved {
		t.Error("Error should be marked as resolved")
	}

	if errorEvent.ResolvedBy != resolvedBy {
		t.Errorf("Expected resolved by %s, got %s", resolvedBy, errorEvent.ResolvedBy)
	}

	if errorEvent.ResolvedAt == nil {
		t.Error("ResolvedAt should not be nil")
	}
}

func TestErrorTracker_GetErrors(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: false,
	}

	tracker := NewErrorTracker(config, nil)

	ctx := context.Background()

	// Create errors with different categories and severities
	errors := []struct {
		err       error
		category  ErrorCategory
		operation string
		component string
	}{
		{errors.New("auth error"), CategoryAuth, "login", "auth"},
		{errors.New("db error"), CategoryDatabase, "query", "postgres"},
		{errors.New("cache error"), CategoryCache, "get", "redis"},
		{errors.New("validation error"), CategoryValidation, "validate", "api"},
	}

	var errorIDs []string
	for _, e := range errors {
		errorID := tracker.TrackError(ctx, e.err, e.category, e.operation, e.component)
		errorIDs = append(errorIDs, errorID)
	}

	// Test getting all errors
	allErrors := tracker.GetErrors("", "", nil)
	if len(allErrors) != len(errors) {
		t.Errorf("Expected %d errors, got %d", len(errors), len(allErrors))
	}

	// Test filtering by category
	authErrors := tracker.GetErrors(CategoryAuth, "", nil)
	if len(authErrors) != 1 {
		t.Errorf("Expected 1 auth error, got %d", len(authErrors))
	}

	// Test filtering by resolved status
	resolved := false
	unresolvedErrors := tracker.GetErrors("", "", &resolved)
	if len(unresolvedErrors) != len(errors) {
		t.Errorf("Expected %d unresolved errors, got %d", len(errors), len(unresolvedErrors))
	}

	// Resolve one error and test again
	tracker.ResolveError(errorIDs[0], "admin")
	unresolvedErrors = tracker.GetErrors("", "", &resolved)
	if len(unresolvedErrors) != len(errors)-1 {
		t.Errorf("Expected %d unresolved errors after resolving one, got %d", len(errors)-1, len(unresolvedErrors))
	}
}

func TestErrorTracker_AddAlertRule(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: true,
		AlertBuffer:     100,
	}

	tracker := NewErrorTracker(config, nil)

	rule := &AlertRule{
		ID:         "test_rule",
		Name:       "Test Rule",
		Category:   CategoryAuth,
		Severity:   SeverityHigh,
		Threshold:  5,
		TimeWindow: 5 * time.Minute,
		Enabled:    true,
		Cooldown:   10 * time.Minute,
	}

	tracker.AddAlertRule(rule)

	// Verify rule was added
	tracker.mu.RLock()
	storedRule, exists := tracker.rules[rule.ID]
	tracker.mu.RUnlock()

	if !exists {
		t.Error("Alert rule was not stored")
	}

	if storedRule.Name != rule.Name {
		t.Errorf("Expected rule name %s, got %s", rule.Name, storedRule.Name)
	}
}

func TestErrorTracker_RemoveAlertRule(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: true,
		AlertBuffer:     100,
	}

	tracker := NewErrorTracker(config, nil)

	rule := &AlertRule{
		ID:         "test_rule",
		Name:       "Test Rule",
		Category:   CategoryAuth,
		Severity:   SeverityHigh,
		Threshold:  5,
		TimeWindow: 5 * time.Minute,
		Enabled:    true,
		Cooldown:   10 * time.Minute,
	}

	tracker.AddAlertRule(rule)
	tracker.RemoveAlertRule(rule.ID)

	// Verify rule was removed
	tracker.mu.RLock()
	_, exists := tracker.rules[rule.ID]
	tracker.mu.RUnlock()

	if exists {
		t.Error("Alert rule should have been removed")
	}
}

func TestErrorTracker_CategorizeErrorSeverity(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: false,
	}

	tracker := NewErrorTracker(config, nil)

	tests := []struct {
		err      error
		category ErrorCategory
		expected ErrorSeverity
	}{
		{errors.New("security breach"), CategorySecurity, SeverityCritical},
		{errors.New("connection timeout"), CategoryDatabase, SeverityHigh},
		{errors.New("unauthorized access"), CategoryAuth, SeverityMedium},
		{errors.New("invalid input"), CategoryValidation, SeverityMedium},
		{errors.New("general error"), CategorySystem, SeverityLow},
	}

	for _, test := range tests {
		severity := tracker.categorizeErrorSeverity(test.err, test.category)
		if severity != test.expected {
			t.Errorf("Expected severity %s for error %s in category %s, got %s",
				test.expected, test.err.Error(), test.category, severity)
		}
	}
}

func TestErrorTracker_GenerateErrorID(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: false,
	}

	tracker := NewErrorTracker(config, nil)

	err1 := errors.New("test error")
	err2 := errors.New("test error")
	err3 := errors.New("different error")

	operation := "test_operation"
	component := "test_component"

	id1 := tracker.generateErrorID(err1, operation, component)
	id2 := tracker.generateErrorID(err2, operation, component)
	id3 := tracker.generateErrorID(err3, operation, component)

	// Same errors should generate same ID
	if id1 != id2 {
		t.Error("Same errors should generate the same ID")
	}

	// Different errors should generate different IDs
	if id1 == id3 {
		t.Error("Different errors should generate different IDs")
	}

	// IDs should not be empty
	if id1 == "" || id3 == "" {
		t.Error("Generated IDs should not be empty")
	}
}

func TestErrorTracker_GetAlerts(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: true,
		AlertBuffer:     100,
	}

	tracker := NewErrorTracker(config, nil)

	// Manually add an alert for testing
	alert := &Alert{
		ID:         "test_alert",
		RuleID:     "test_rule",
		RuleName:   "Test Rule",
		Timestamp:  time.Now(),
		Severity:   SeverityHigh,
		Message:    "Test alert message",
		ErrorCount: 5,
		TimeWindow: 5 * time.Minute,
		Resolved:   false,
	}

	tracker.mu.Lock()
	tracker.alerts[alert.ID] = alert
	tracker.mu.Unlock()

	// Test getting all alerts
	allAlerts := tracker.GetAlerts(nil)
	if len(allAlerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(allAlerts))
	}

	// Test filtering by resolved status
	resolved := false
	unresolvedAlerts := tracker.GetAlerts(&resolved)
	if len(unresolvedAlerts) != 1 {
		t.Errorf("Expected 1 unresolved alert, got %d", len(unresolvedAlerts))
	}

	resolved = true
	resolvedAlerts := tracker.GetAlerts(&resolved)
	if len(resolvedAlerts) != 0 {
		t.Errorf("Expected 0 resolved alerts, got %d", len(resolvedAlerts))
	}
}

func TestErrorTracker_GetAlertChannel(t *testing.T) {
	config := ErrorTrackerConfig{
		Enabled:         true,
		MaxErrors:       1000,
		RetentionPeriod: 24 * time.Hour,
		AlertingEnabled: true,
		AlertBuffer:     100,
	}

	tracker := NewErrorTracker(config, nil)

	alertChan := tracker.GetAlertChannel()
	if alertChan == nil {
		t.Error("GetAlertChannel() returned nil")
	}

	// Test that the channel is the same instance
	alertChan2 := tracker.GetAlertChannel()
	if alertChan != alertChan2 {
		t.Error("GetAlertChannel() should return the same channel instance")
	}
}
