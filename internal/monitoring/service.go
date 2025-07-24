package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Service provides monitoring capabilities including metrics and logging
type Service struct {
	metrics      *Metrics
	logger       *Logger
	collector    *MetricsCollector
	registry     *prometheus.Registry
	errorTracker *ErrorTracker
	aggregator   *LogAggregator
}

// Config contains configuration for the monitoring service
type Config struct {
	Enabled      bool                `yaml:"enabled"`
	Prometheus   PrometheusConfig    `yaml:"prometheus"`
	Logging      LoggerConfig        `yaml:"logging"`
	ErrorTracker ErrorTrackerConfig  `yaml:"error_tracker"`
	Aggregator   LogAggregatorConfig `yaml:"log_aggregator"`
	Tracing      TracingConfig       `yaml:"tracing"`
}

// TracingConfig contains distributed tracing configuration
type TracingConfig struct {
	Enabled        bool    `yaml:"enabled"`
	ServiceName    string  `yaml:"service_name"`
	ServiceVersion string  `yaml:"service_version"`
	SampleRate     float64 `yaml:"sample_rate"`
}

// PrometheusConfig contains Prometheus-specific configuration
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Port    int    `yaml:"port"`
}

// NewService creates a new monitoring service
func NewService(config Config) (*Service, error) {
	if !config.Enabled {
		return &Service{}, nil
	}

	// Create logger
	logger, err := NewLogger(config.Logging)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create Prometheus registry
	registry := prometheus.NewRegistry()

	// Create metrics
	metrics := NewMetrics(registry)

	// Create metrics collector
	collector := NewMetricsCollector(metrics)

	// Create error tracker
	var errorTracker *ErrorTracker
	if config.ErrorTracker.Enabled {
		errorTracker = NewErrorTracker(config.ErrorTracker, logger)
	}

	// Create log aggregator
	var aggregator *LogAggregator
	if config.Aggregator.Enabled {
		aggregator = NewLogAggregator(config.Aggregator, logger)
	}

	service := &Service{
		metrics:      metrics,
		logger:       logger,
		collector:    collector,
		registry:     registry,
		errorTracker: errorTracker,
		aggregator:   aggregator,
	}

	logger.Info("Monitoring service initialized")

	return service, nil
}

// GetMetrics returns the metrics instance
func (s *Service) GetMetrics() *Metrics {
	return s.metrics
}

// GetLogger returns the logger instance
func (s *Service) GetLogger() *Logger {
	return s.logger
}

// GetRegistry returns the Prometheus registry
func (s *Service) GetRegistry() *prometheus.Registry {
	return s.registry
}

// GetErrorTracker returns the error tracker instance
func (s *Service) GetErrorTracker() *ErrorTracker {
	return s.errorTracker
}

// GetLogAggregator returns the log aggregator instance
func (s *Service) GetLogAggregator() *LogAggregator {
	return s.aggregator
}

// StartCollection starts periodic metrics collection
func (s *Service) StartCollection(ctx context.Context, interval time.Duration) {
	if s.collector == nil {
		return
	}

	s.logger.Info("Starting metrics collection", "interval", interval)
	go s.collector.StartPeriodicCollection(ctx, interval)
}

// MetricsHandler returns an HTTP handler for Prometheus metrics
func (s *Service) MetricsHandler() http.Handler {
	if s.metrics == nil {
		return http.NotFoundHandler()
	}
	return s.metrics.Handler()
}

// HealthCheck performs a health check of the monitoring system
func (s *Service) HealthCheck(ctx context.Context) error {
	if s.metrics != nil {
		// Test metrics by recording a health check metric
		s.metrics.SetSystemHealth("monitoring", true)
	}

	if s.logger != nil {
		// Test logger by writing a health check log
		s.logger.WithContext(ctx).Debug("Monitoring health check")
	}

	return nil
}

// RecordAuthEvent records an authentication event with both metrics and logs
func (s *Service) RecordAuthEvent(ctx context.Context, method string, userID string, success bool, duration time.Duration, details map[string]interface{}) {
	if s.metrics != nil {
		if success {
			s.metrics.RecordAuthSuccess(method, "user")
			s.metrics.RecordAuthAttempt(method, "success")
		} else {
			reason := "unknown"
			if r, ok := details["reason"].(string); ok {
				reason = r
			}
			s.metrics.RecordAuthFailure(method, reason)
			s.metrics.RecordAuthAttempt(method, "failure")
		}
		s.metrics.RecordAuthDuration(method, map[bool]string{true: "success", false: "failure"}[success], duration)
	}

	if s.logger != nil {
		s.logger.AuthEvent(ctx, method, userID, success, details)
	}
}

// RecordTokenEvent records a token-related event
func (s *Service) RecordTokenEvent(ctx context.Context, operation string, tokenType string, success bool, details map[string]interface{}) {
	if s.metrics != nil {
		switch operation {
		case "generate":
			s.metrics.RecordTokenGeneration(tokenType)
		case "validate":
			result := map[bool]string{true: "success", false: "failure"}[success]
			s.metrics.RecordTokenValidation(tokenType, result)
		case "refresh":
			result := map[bool]string{true: "success", false: "failure"}[success]
			s.metrics.RecordTokenRefresh(result)
		}
	}

	if s.logger != nil {
		fields := map[string]interface{}{
			"operation":  operation,
			"token_type": tokenType,
			"success":    success,
		}
		for k, v := range details {
			fields[k] = v
		}

		if success {
			s.logger.WithContext(ctx).WithFields(fields).Info("Token operation")
		} else {
			s.logger.WithContext(ctx).WithFields(fields).Warn("Token operation failed")
		}
	}
}

// RecordUserEvent records a user management event
func (s *Service) RecordUserEvent(ctx context.Context, operation string, userID string, details map[string]interface{}) {
	if s.metrics != nil {
		switch operation {
		case "register":
			method := "direct"
			if m, ok := details["method"].(string); ok {
				method = m
			}
			s.metrics.RecordUserRegistration(method)
		case "login":
			method := "password"
			if m, ok := details["method"].(string); ok {
				method = m
			}
			s.metrics.RecordUserLogin(method)
		case "logout":
			s.metrics.RecordUserLogout()
		case "profile_update":
			field := "general"
			if f, ok := details["field"].(string); ok {
				field = f
			}
			s.metrics.RecordProfileUpdate(field)
		}
	}

	if s.logger != nil {
		fields := map[string]interface{}{
			"operation": operation,
			"user_id":   userID,
		}
		for k, v := range details {
			fields[k] = v
		}

		s.logger.WithContext(ctx).WithFields(fields).Info("User event")
	}
}

// RecordMFAEvent records an MFA-related event
func (s *Service) RecordMFAEvent(ctx context.Context, method string, success bool, reason string, details map[string]interface{}) {
	if s.metrics != nil {
		s.metrics.RecordMFAAttempt(method)
		if success {
			s.metrics.RecordMFASuccess(method)
		} else {
			s.metrics.RecordMFAFailure(method, reason)
		}
	}

	if s.logger != nil {
		fields := map[string]interface{}{
			"method":  method,
			"success": success,
		}
		if !success {
			fields["reason"] = reason
		}
		for k, v := range details {
			fields[k] = v
		}

		if success {
			s.logger.WithContext(ctx).WithFields(fields).Info("MFA verification")
		} else {
			s.logger.WithContext(ctx).WithFields(fields).Warn("MFA verification failed")
		}
	}
}

// RecordDatabaseEvent records a database operation event
func (s *Service) RecordDatabaseEvent(ctx context.Context, operation string, table string, duration time.Duration, err error) {
	if s.metrics != nil {
		s.metrics.RecordDatabaseQuery(operation, table, duration)
		if err != nil {
			errorType := "unknown"
			// You could categorize errors here
			s.metrics.RecordDatabaseError(operation, errorType)
		}
	}

	if s.logger != nil {
		s.logger.DatabaseEvent(ctx, operation, table, duration, err)
	}
}

// RecordCacheEvent records a cache operation event
func (s *Service) RecordCacheEvent(ctx context.Context, cacheType string, operation string, key string, hit bool, duration time.Duration, err error) {
	if s.metrics != nil {
		if hit {
			s.metrics.RecordCacheHit(cacheType, operation)
		} else {
			s.metrics.RecordCacheMiss(cacheType, operation)
		}

		result := "success"
		if err != nil {
			result = "error"
		}
		s.metrics.RecordCacheOperation(cacheType, operation, result, duration)
	}

	if s.logger != nil {
		s.logger.CacheEvent(ctx, operation, key, hit, duration)
	}
}

// RecordHTTPEvent records an HTTP request event
func (s *Service) RecordHTTPEvent(ctx context.Context, method string, endpoint string, statusCode int, duration time.Duration, requestSize int64, responseSize int64, userAgent string, clientIP string) {
	if s.metrics != nil {
		s.metrics.RecordHTTPRequest(method, endpoint, fmt.Sprintf("%d", statusCode), duration, requestSize, responseSize)
	}

	if s.logger != nil {
		s.logger.HTTPEvent(ctx, method, endpoint, statusCode, duration, userAgent, clientIP)
	}
}

// RecordGRPCEvent records a gRPC request event
func (s *Service) RecordGRPCEvent(ctx context.Context, service string, method string, statusCode string, duration time.Duration, clientIP string) {
	if s.metrics != nil {
		s.metrics.RecordGRPCRequest(service, method, statusCode, duration)
	}

	if s.logger != nil {
		s.logger.GRPCEvent(ctx, service, method, statusCode, duration, clientIP)
	}
}

// RecordRateLimitEvent records a rate limiting event
func (s *Service) RecordRateLimitEvent(ctx context.Context, limiterType string, identifier string, blocked bool, details map[string]interface{}) {
	if s.metrics != nil {
		if blocked {
			s.metrics.RecordRateLimitBlock(limiterType, identifier)
		} else {
			s.metrics.RecordRateLimitHit(limiterType, identifier)
		}
	}

	if s.logger != nil {
		fields := map[string]interface{}{
			"limiter_type": limiterType,
			"identifier":   identifier,
			"blocked":      blocked,
		}
		for k, v := range details {
			fields[k] = v
		}

		if blocked {
			s.logger.SecurityEvent(ctx, "rate_limit_exceeded", "medium", fields)
		} else {
			s.logger.WithContext(ctx).WithFields(fields).Debug("Rate limit check")
		}
	}
}

// RecordSecurityEvent records a security-related event
func (s *Service) RecordSecurityEvent(ctx context.Context, event string, severity string, details map[string]interface{}) {
	if s.logger != nil {
		s.logger.SecurityEvent(ctx, event, severity, details)
	}

	// Add to log aggregator if enabled
	if s.aggregator != nil {
		entry := LogEntry{
			Timestamp:     time.Now(),
			Level:         "warn",
			Message:       event,
			EventType:     "security",
			Component:     "auth",
			Operation:     event,
			UserID:        getStringFromContext(ctx, "user_id"),
			RequestID:     getStringFromContext(ctx, "request_id"),
			TraceID:       getStringFromContext(ctx, "trace_id"),
			CorrelationID: getStringFromContext(ctx, "correlation_id"),
			ClientIP:      getStringFromContext(ctx, "client_ip"),
			Fields:        details,
		}
		s.aggregator.AddLogEntry(entry)
	}
}

// RecordAuditEvent records an audit trail event
func (s *Service) RecordAuditEvent(ctx context.Context, action string, resource string, userID string, details map[string]interface{}) {
	if s.logger != nil {
		s.logger.AuditEvent(ctx, action, resource, userID, details)
	}
}

// UpdateSystemHealth updates system health metrics
func (s *Service) UpdateSystemHealth(component string, healthy bool) {
	if s.metrics != nil {
		s.metrics.SetSystemHealth(component, healthy)
	}
}

// UpdateActiveSessions updates active session count
func (s *Service) UpdateActiveSessions(sessionType string, count int) {
	if s.metrics != nil {
		s.metrics.SetActiveSessions(sessionType, count)
	}
}

// UpdateDatabaseConnections updates database connection metrics
func (s *Service) UpdateDatabaseConnections(active, idle, max int) {
	if s.metrics != nil {
		s.metrics.RecordDatabaseConnections(active, idle, max)
	}
}

// TrackError tracks an error with the error tracker
func (s *Service) TrackError(ctx context.Context, err error, category ErrorCategory, operation, component string) string {
	if s.errorTracker != nil {
		return s.errorTracker.TrackError(ctx, err, category, operation, component)
	}
	return ""
}

// StartTrace starts a new distributed trace
func (s *Service) StartTrace(ctx context.Context, operation string) (*TraceContext, context.Context) {
	if s.logger != nil {
		return s.logger.StartTrace(ctx, operation)
	}
	return nil, ctx
}

// FinishTrace completes a distributed trace
func (s *Service) FinishTrace(ctx context.Context, trace *TraceContext, err error) {
	if s.logger != nil {
		s.logger.FinishTrace(ctx, trace, err)
	}
}

// AddTraceTag adds a tag to the current trace
func (s *Service) AddTraceTag(ctx context.Context, key, value string) {
	if s.logger != nil {
		s.logger.AddTraceTag(ctx, key, value)
	}
}

// CreateCorrelation creates a new correlation context
func (s *Service) CreateCorrelation(requestID, sessionID, userID, clientIP, userAgent string) *CorrelationContext {
	if s.logger != nil {
		return s.logger.CreateCorrelation(requestID, sessionID, userID, clientIP, userAgent)
	}
	return nil
}

// WithCorrelation adds correlation context to the logger
func (s *Service) WithCorrelation(ctx context.Context, correlation *CorrelationContext) context.Context {
	if s.logger != nil {
		return s.logger.WithCorrelation(ctx, correlation)
	}
	return ctx
}

// SearchLogs searches log entries
func (s *Service) SearchLogs(query LogSearchQuery) []*LogEntry {
	if s.aggregator != nil {
		return s.aggregator.SearchLogs(query)
	}
	return nil
}

// GetLogStatistics returns log statistics
func (s *Service) GetLogStatistics(start, end time.Time) *LogStatistics {
	if s.aggregator != nil {
		return s.aggregator.GetLogStatistics(start, end)
	}
	return nil
}

// GetLogMetrics returns aggregated log metrics
func (s *Service) GetLogMetrics(eventType, component string, level AggregationLevel, start, end time.Time) []*LogMetric {
	if s.aggregator != nil {
		return s.aggregator.GetMetrics(eventType, component, level, start, end)
	}
	return nil
}

// GetLogPatterns returns detected log patterns
func (s *Service) GetLogPatterns(eventType, component string) []*LogPattern {
	if s.aggregator != nil {
		return s.aggregator.GetPatterns(eventType, component)
	}
	return nil
}

// GetErrors returns tracked errors
func (s *Service) GetErrors(category ErrorCategory, severity ErrorSeverity, resolved *bool) []*ErrorEvent {
	if s.errorTracker != nil {
		return s.errorTracker.GetErrors(category, severity, resolved)
	}
	return nil
}

// GetAlerts returns alerts
func (s *Service) GetAlerts(resolved *bool) []*Alert {
	if s.errorTracker != nil {
		return s.errorTracker.GetAlerts(resolved)
	}
	return nil
}

// GetAlertChannel returns the alert channel
func (s *Service) GetAlertChannel() <-chan *Alert {
	if s.errorTracker != nil {
		return s.errorTracker.GetAlertChannel()
	}
	return nil
}

// ResolveError marks an error as resolved
func (s *Service) ResolveError(errorID, resolvedBy string) {
	if s.errorTracker != nil {
		s.errorTracker.ResolveError(errorID, resolvedBy)
	}
}

// AddErrorContext adds context to an error
func (s *Service) AddErrorContext(errorID string, key string, value interface{}) {
	if s.errorTracker != nil {
		s.errorTracker.AddErrorContext(errorID, key, value)
	}
}

// ExportLogMetrics exports log metrics
func (s *Service) ExportLogMetrics(format string) ([]byte, error) {
	if s.aggregator != nil {
		return s.aggregator.ExportMetrics(format)
	}
	return nil, fmt.Errorf("log aggregator not enabled")
}

// RecordMFAAttempt records an MFA attempt
func (s *Service) RecordMFAAttempt(method string) {
	if s.metrics != nil {
		s.metrics.RecordMFAAttempt(method)
	}
}

// RecordMFASuccess records a successful MFA verification
func (s *Service) RecordMFASuccess(method string) {
	if s.metrics != nil {
		s.metrics.RecordMFASuccess(method)
	}
}

// RecordMFAFailure records a failed MFA verification
func (s *Service) RecordMFAFailure(method, reason string) {
	if s.metrics != nil {
		s.metrics.RecordMFAFailure(method, reason)
	}
}

// Close closes the monitoring service and any open resources
func (s *Service) Close() error {
	if s.logger != nil {
		s.logger.Info("Shutting down monitoring service")
		return s.logger.Close()
	}
	return nil
}
