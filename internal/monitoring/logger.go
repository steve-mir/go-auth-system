package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel represents the severity level of a log entry
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// LogFormat represents the format of log output
type LogFormat string

const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

// Logger provides structured logging capabilities
type Logger struct {
	*slog.Logger
	level  LogLevel
	format LogFormat
}

// LoggerConfig contains configuration for the logger
type LoggerConfig struct {
	Level  LogLevel  `yaml:"level"`
	Format LogFormat `yaml:"format"`
	Output string    `yaml:"output"` // "stdout", "stderr", or file path
}

// NewLogger creates a new structured logger
func NewLogger(config LoggerConfig) (*Logger, error) {
	var writer io.Writer

	// Determine output destination
	switch config.Output {
	case "", "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// Assume it's a file path
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = file
	}

	// Convert log level
	var slogLevel slog.Level
	switch config.Level {
	case LogLevelDebug:
		slogLevel = slog.LevelDebug
	case LogLevelInfo:
		slogLevel = slog.LevelInfo
	case LogLevelWarn:
		slogLevel = slog.LevelWarn
	case LogLevelError:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	// Create handler based on format
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level:     slogLevel,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize timestamp format
			if a.Key == slog.TimeKey {
				return slog.String("timestamp", a.Value.Time().Format(time.RFC3339))
			}
			// Shorten source file paths
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				if source != nil {
					// Get just the filename and line number
					parts := strings.Split(source.File, "/")
					if len(parts) > 0 {
						source.File = parts[len(parts)-1]
					}
				}
			}
			return a
		},
	}

	switch config.Format {
	case LogFormatJSON:
		handler = slog.NewJSONHandler(writer, opts)
	case LogFormatText:
		handler = slog.NewTextHandler(writer, opts)
	default:
		handler = slog.NewJSONHandler(writer, opts)
	}

	logger := slog.New(handler)

	return &Logger{
		Logger: logger,
		level:  config.Level,
		format: config.Format,
	}, nil
}

// WithContext returns a logger with context values
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract common context values
	attrs := make([]slog.Attr, 0)

	if traceID := ctx.Value("trace_id"); traceID != nil {
		attrs = append(attrs, slog.String("trace_id", fmt.Sprintf("%v", traceID)))
	}

	if userID := ctx.Value("user_id"); userID != nil {
		attrs = append(attrs, slog.String("user_id", fmt.Sprintf("%v", userID)))
	}

	if requestID := ctx.Value("request_id"); requestID != nil {
		attrs = append(attrs, slog.String("request_id", fmt.Sprintf("%v", requestID)))
	}

	if len(attrs) > 0 {
		return &Logger{
			Logger: l.Logger.With(attrs...),
			level:  l.level,
			format: l.format,
		}
	}

	return l
}

// WithFields returns a logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	attrs := make([]slog.Attr, 0, len(fields))
	for key, value := range fields {
		attrs = append(attrs, slog.Any(key, value))
	}

	return &Logger{
		Logger: l.Logger.With(attrs...),
		level:  l.level,
		format: l.format,
	}
}

// WithError returns a logger with error information
func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}

	attrs := []slog.Attr{
		slog.String("error", err.Error()),
		slog.String("error_type", fmt.Sprintf("%T", err)),
	}

	// Add stack trace for debug level
	if l.level == LogLevelDebug {
		attrs = append(attrs, slog.String("stack_trace", getStackTrace()))
	}

	return &Logger{
		Logger: l.Logger.With(attrs...),
		level:  l.level,
		format: l.format,
	}
}

// AuthEvent logs authentication-related events
func (l *Logger) AuthEvent(ctx context.Context, event string, userID string, success bool, details map[string]interface{}) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type": "authentication",
		"event":      event,
		"user_id":    userID,
		"success":    success,
	}

	// Add additional details
	for key, value := range details {
		fields[key] = value
	}

	if success {
		logger.WithFields(fields).Info("Authentication event")
	} else {
		logger.WithFields(fields).Warn("Authentication failed")
	}
}

// SecurityEvent logs security-related events
func (l *Logger) SecurityEvent(ctx context.Context, event string, severity string, details map[string]interface{}) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type": "security",
		"event":      event,
		"severity":   severity,
	}

	// Add additional details
	for key, value := range details {
		fields[key] = value
	}

	switch severity {
	case "low":
		logger.WithFields(fields).Info("Security event")
	case "medium":
		logger.WithFields(fields).Warn("Security event")
	case "high", "critical":
		logger.WithFields(fields).Error("Security event")
	default:
		logger.WithFields(fields).Info("Security event")
	}
}

// AuditEvent logs audit trail events
func (l *Logger) AuditEvent(ctx context.Context, action string, resource string, userID string, details map[string]interface{}) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type": "audit",
		"action":     action,
		"resource":   resource,
		"user_id":    userID,
		"timestamp":  time.Now().UTC(),
	}

	// Add additional details
	for key, value := range details {
		fields[key] = value
	}

	logger.WithFields(fields).Info("Audit event")
}

// PerformanceEvent logs performance-related events
func (l *Logger) PerformanceEvent(ctx context.Context, operation string, duration time.Duration, details map[string]interface{}) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type":       "performance",
		"operation":        operation,
		"duration_ms":      duration.Milliseconds(),
		"duration_seconds": duration.Seconds(),
	}

	// Add additional details
	for key, value := range details {
		fields[key] = value
	}

	// Log as warning if operation took too long
	if duration > 5*time.Second {
		logger.WithFields(fields).Warn("Slow operation detected")
	} else if duration > 1*time.Second {
		logger.WithFields(fields).Info("Performance event")
	} else {
		logger.WithFields(fields).Debug("Performance event")
	}
}

// DatabaseEvent logs database-related events
func (l *Logger) DatabaseEvent(ctx context.Context, operation string, table string, duration time.Duration, err error) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type":  "database",
		"operation":   operation,
		"table":       table,
		"duration_ms": duration.Milliseconds(),
	}

	if err != nil {
		logger.WithError(err).WithFields(fields).Error("Database operation failed")
	} else {
		if duration > 1*time.Second {
			logger.WithFields(fields).Warn("Slow database operation")
		} else {
			logger.WithFields(fields).Debug("Database operation")
		}
	}
}

// CacheEvent logs cache-related events
func (l *Logger) CacheEvent(ctx context.Context, operation string, key string, hit bool, duration time.Duration) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type":  "cache",
		"operation":   operation,
		"key":         key,
		"hit":         hit,
		"duration_ms": duration.Milliseconds(),
	}

	logger.WithFields(fields).Debug("Cache operation")
}

// HTTPEvent logs HTTP request events
func (l *Logger) HTTPEvent(ctx context.Context, method string, path string, statusCode int, duration time.Duration, userAgent string, clientIP string) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type":  "http",
		"method":      method,
		"path":        path,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
		"user_agent":  userAgent,
		"client_ip":   clientIP,
	}

	if statusCode >= 500 {
		logger.WithFields(fields).Error("HTTP server error")
	} else if statusCode >= 400 {
		logger.WithFields(fields).Warn("HTTP client error")
	} else {
		logger.WithFields(fields).Info("HTTP request")
	}
}

// GRPCEvent logs gRPC request events
func (l *Logger) GRPCEvent(ctx context.Context, service string, method string, statusCode string, duration time.Duration, clientIP string) {
	logger := l.WithContext(ctx)

	fields := map[string]interface{}{
		"event_type":  "grpc",
		"service":     service,
		"method":      method,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
		"client_ip":   clientIP,
	}

	if strings.Contains(statusCode, "Error") || strings.Contains(statusCode, "Failed") {
		logger.WithFields(fields).Error("gRPC request failed")
	} else {
		logger.WithFields(fields).Info("gRPC request")
	}
}

// getStackTrace returns a formatted stack trace
func getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])

	var trace strings.Builder
	for {
		frame, more := frames.Next()
		if !more {
			break
		}

		// Skip runtime and logging frames
		if strings.Contains(frame.File, "runtime/") ||
			strings.Contains(frame.File, "log/") ||
			strings.Contains(frame.File, "monitoring/") {
			continue
		}

		fmt.Fprintf(&trace, "%s:%d %s\n", frame.File, frame.Line, frame.Function)
	}

	return trace.String()
}

// LogEntry represents a structured log entry for JSON marshaling
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Source    string                 `json:"source,omitempty"`
}

// MarshalJSON implements json.Marshaler for custom JSON formatting
func (l *Logger) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"level":  l.level,
		"format": l.format,
	})
}

// Close closes any open file handles
func (l *Logger) Close() error {
	// If we opened a file, we should close it
	// This would require keeping track of the file handle
	// For now, this is a no-op as we don't track file handles
	return nil
}
