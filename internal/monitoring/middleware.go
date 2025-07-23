package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// HTTPMiddleware creates a Gin middleware for HTTP request monitoring
func (s *Service) HTTPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || s.metrics == nil {
			c.Next()
			return
		}

		start := time.Now()

		// Get request size
		requestSize := int64(0)
		if c.Request.ContentLength > 0 {
			requestSize = c.Request.ContentLength
		}

		// Create a response writer wrapper to capture response size
		wrapper := &responseWriterWrapper{
			ResponseWriter: c.Writer,
			size:           0,
		}
		c.Writer = wrapper

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Get client information
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Normalize endpoint path (remove IDs and parameters)
		endpoint := normalizeEndpoint(c.Request.URL.Path)

		// Record metrics and logs
		s.RecordHTTPEvent(
			c.Request.Context(),
			c.Request.Method,
			endpoint,
			c.Writer.Status(),
			duration,
			requestSize,
			int64(wrapper.size),
			userAgent,
			clientIP,
		)
	}
}

// responseWriterWrapper wraps gin.ResponseWriter to capture response size
type responseWriterWrapper struct {
	gin.ResponseWriter
	size int
}

func (w *responseWriterWrapper) Write(data []byte) (int, error) {
	size, err := w.ResponseWriter.Write(data)
	w.size += size
	return size, err
}

func (w *responseWriterWrapper) WriteString(s string) (int, error) {
	size, err := w.ResponseWriter.WriteString(s)
	w.size += size
	return size, err
}

// GRPCUnaryInterceptor creates a gRPC unary interceptor for request monitoring
func (s *Service) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if s == nil || s.metrics == nil {
			return handler(ctx, req)
		}

		start := time.Now()

		// Get client IP
		clientIP := getClientIP(ctx)

		// Process request
		resp, err := handler(ctx, req)

		// Calculate duration
		duration := time.Since(start)

		// Get status code
		statusCode := "OK"
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code().String()
			} else {
				statusCode = "Unknown"
			}
		}

		// Extract service and method names
		service, method := parseGRPCMethod(info.FullMethod)

		// Record metrics and logs
		s.RecordGRPCEvent(ctx, service, method, statusCode, duration, clientIP)

		return resp, err
	}
}

// GRPCStreamInterceptor creates a gRPC stream interceptor for request monitoring
func (s *Service) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if s == nil || s.metrics == nil {
			return handler(srv, stream)
		}

		start := time.Now()
		ctx := stream.Context()

		// Get client IP
		clientIP := getClientIP(ctx)

		// Process stream
		err := handler(srv, stream)

		// Calculate duration
		duration := time.Since(start)

		// Get status code
		statusCode := "OK"
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code().String()
			} else {
				statusCode = "Unknown"
			}
		}

		// Extract service and method names
		service, method := parseGRPCMethod(info.FullMethod)

		// Record metrics and logs
		s.RecordGRPCEvent(ctx, service, method, statusCode, duration, clientIP)

		return err
	}
}

// DatabaseMiddleware creates a middleware function for database operations
func (s *Service) DatabaseMiddleware() func(operation, table string, fn func() error) error {
	return func(operation, table string, fn func() error) error {
		if s == nil {
			return fn()
		}

		start := time.Now()
		err := fn()
		duration := time.Since(start)

		// Record database event
		s.RecordDatabaseEvent(context.Background(), operation, table, duration, err)

		return err
	}
}

// CacheMiddleware creates a middleware function for cache operations
func (s *Service) CacheMiddleware() func(ctx context.Context, cacheType, operation, key string, fn func() (bool, error)) (bool, error) {
	return func(ctx context.Context, cacheType, operation, key string, fn func() (bool, error)) (bool, error) {
		if s == nil {
			hit, err := fn()
			return hit, err
		}

		start := time.Now()
		hit, err := fn()
		duration := time.Since(start)

		// Record cache event
		s.RecordCacheEvent(ctx, cacheType, operation, key, hit, duration, err)

		return hit, err
	}
}

// AuthMiddleware creates a middleware function for authentication operations
func (s *Service) AuthMiddleware() func(ctx context.Context, method, userID string, fn func() error) error {
	return func(ctx context.Context, method, userID string, fn func() error) error {
		if s == nil {
			return fn()
		}

		start := time.Now()
		err := fn()
		duration := time.Since(start)
		success := err == nil

		details := make(map[string]interface{})
		if err != nil {
			details["error"] = err.Error()
			details["reason"] = categorizeAuthError(err)
		}

		// Record authentication event
		s.RecordAuthEvent(ctx, method, userID, success, duration, details)

		return err
	}
}

// normalizeEndpoint removes IDs and parameters from URL paths for better metric grouping
func normalizeEndpoint(path string) string {
	// Common patterns to normalize
	patterns := []struct {
		pattern     string
		replacement string
	}{
		{`/\d+`, "/{id}"},                // Replace numeric IDs
		{`/[a-f0-9-]{36}`, "/{uuid}"},    // Replace UUIDs
		{`/[a-f0-9]{24}`, "/{objectid}"}, // Replace MongoDB ObjectIDs
		{`\?.*`, ""},                     // Remove query parameters
	}

	normalized := path

	// For simplicity, we'll do basic string replacement
	if strings.Contains(normalized, "?") {
		parts := strings.Split(normalized, "?")
		normalized = parts[0]
	}

	// Apply regex patterns for more advanced replacements
	for _, pat := range patterns {
		re := regexp.MustCompile(pat.pattern)
		normalized = re.ReplaceAllString(normalized, pat.replacement)
	}

	return normalized
}

// parseGRPCMethod extracts service and method names from gRPC full method
func parseGRPCMethod(fullMethod string) (service, method string) {
	// fullMethod format: /package.Service/Method
	parts := strings.Split(fullMethod, "/")
	if len(parts) >= 3 {
		serviceParts := strings.Split(parts[1], ".")
		if len(serviceParts) > 0 {
			service = serviceParts[len(serviceParts)-1]
		}
		method = parts[2]
	}
	return service, method
}

// getClientIP extracts client IP from gRPC context
func getClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}

	// Try to get from metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xForwardedFor := md.Get("x-forwarded-for"); len(xForwardedFor) > 0 {
			return xForwardedFor[0]
		}
		if xRealIP := md.Get("x-real-ip"); len(xRealIP) > 0 {
			return xRealIP[0]
		}
	}

	return "unknown"
}

// categorizeAuthError categorizes authentication errors for better metrics
func categorizeAuthError(err error) string {
	if err == nil {
		return ""
	}

	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "password"):
		return "invalid_password"
	case strings.Contains(errStr, "user") && strings.Contains(errStr, "not found"):
		return "user_not_found"
	case strings.Contains(errStr, "token"):
		return "invalid_token"
	case strings.Contains(errStr, "expired"):
		return "expired_credentials"
	case strings.Contains(errStr, "locked"):
		return "account_locked"
	case strings.Contains(errStr, "disabled"):
		return "account_disabled"
	case strings.Contains(errStr, "rate limit"):
		return "rate_limited"
	case strings.Contains(errStr, "mfa"):
		return "mfa_required"
	default:
		return "unknown"
	}
}

// HealthCheckMiddleware creates middleware for health check endpoints
func (s *Service) HealthCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip monitoring for health check endpoints to avoid noise
		if strings.HasPrefix(c.Request.URL.Path, "/health") ||
			strings.HasPrefix(c.Request.URL.Path, "/metrics") ||
			strings.HasPrefix(c.Request.URL.Path, "/ready") ||
			strings.HasPrefix(c.Request.URL.Path, "/live") {
			c.Next()
			return
		}

		// Continue with normal monitoring
		s.HTTPMiddleware()(c)
	}
}

// RequestIDMiddleware adds request ID to context for tracing
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID (in production, use a proper UUID library)
			requestID = strconv.FormatInt(time.Now().UnixNano(), 36)
		}

		// Add to context
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		// Add to response headers
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// TraceIDMiddleware adds trace ID to context for distributed tracing
func TraceIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			// Generate a simple trace ID (in production, use a proper tracing library)
			traceID = strconv.FormatInt(time.Now().UnixNano(), 36)
		}

		// Add to context
		ctx := context.WithValue(c.Request.Context(), "trace_id", traceID)
		c.Request = c.Request.WithContext(ctx)

		// Add to response headers
		c.Header("X-Trace-ID", traceID)

		c.Next()
	}
}

// CorrelationMiddleware creates correlation context for request tracking
func (s *Service) CorrelationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || s.logger == nil {
			c.Next()
			return
		}

		// Get or generate correlation ID
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = generateID()
		}

		// Get request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateID()
		}

		// Get session ID from cookie or header
		sessionID := c.GetHeader("X-Session-ID")
		if sessionID == "" {
			if cookie, err := c.Cookie("session_id"); err == nil {
				sessionID = cookie
			}
		}

		// Get user ID from context (if authenticated)
		userID := ""
		if user := c.GetHeader("X-User-ID"); user != "" {
			userID = user
		}

		// Create correlation context
		correlation := s.CreateCorrelation(
			requestID,
			sessionID,
			userID,
			c.ClientIP(),
			c.Request.UserAgent(),
		)

		// Add correlation to context
		ctx := s.WithCorrelation(c.Request.Context(), correlation)
		c.Request = c.Request.WithContext(ctx)

		// Add headers to response
		c.Header("X-Correlation-ID", correlationID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// TracingMiddleware creates distributed traces for requests
func (s *Service) TracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || s.logger == nil {
			c.Next()
			return
		}

		// Create operation name from method and path
		operation := fmt.Sprintf("%s %s", c.Request.Method, normalizeEndpoint(c.Request.URL.Path))

		// Start trace
		trace, ctx := s.StartTrace(c.Request.Context(), operation)
		c.Request = c.Request.WithContext(ctx)

		// Add trace tags
		s.AddTraceTag(ctx, "http.method", c.Request.Method)
		s.AddTraceTag(ctx, "http.url", c.Request.URL.Path)
		s.AddTraceTag(ctx, "http.user_agent", c.Request.UserAgent())
		s.AddTraceTag(ctx, "client.ip", c.ClientIP())

		// Process request
		c.Next()

		// Add response tags
		s.AddTraceTag(ctx, "http.status_code", strconv.Itoa(c.Writer.Status()))

		// Finish trace
		var err error
		if c.Writer.Status() >= 400 {
			err = fmt.Errorf("HTTP %d", c.Writer.Status())
		}
		s.FinishTrace(ctx, trace, err)
	}
}

// ErrorTrackingMiddleware tracks errors automatically
func (s *Service) ErrorTrackingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || s.errorTracker == nil {
			c.Next()
			return
		}

		// Process request
		c.Next()

		// Check for errors
		if len(c.Errors) > 0 {
			for _, ginErr := range c.Errors {
				category := CategorySystem
				if c.Writer.Status() >= 400 && c.Writer.Status() < 500 {
					category = CategoryValidation
				} else if c.Writer.Status() >= 500 {
					category = CategorySystem
				}

				operation := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
				s.TrackError(c.Request.Context(), ginErr.Err, category, operation, "http")
			}
		}

		// Track HTTP errors based on status code
		if c.Writer.Status() >= 500 {
			err := fmt.Errorf("HTTP %d: %s", c.Writer.Status(), http.StatusText(c.Writer.Status()))
			operation := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
			s.TrackError(c.Request.Context(), err, CategorySystem, operation, "http")
		}
	}
}

// LogAggregationMiddleware adds log entries to the aggregator
func (s *Service) LogAggregationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || s.aggregator == nil {
			c.Next()
			return
		}

		start := time.Now()

		// Process request
		c.Next()

		// Create log entry
		duration := time.Since(start)
		level := "info"
		if c.Writer.Status() >= 500 {
			level = "error"
		} else if c.Writer.Status() >= 400 {
			level = "warn"
		}

		entry := LogEntry{
			Timestamp:     start,
			Level:         level,
			Message:       fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path),
			EventType:     "http",
			Component:     "api",
			Operation:     fmt.Sprintf("%s %s", c.Request.Method, normalizeEndpoint(c.Request.URL.Path)),
			Duration:      float64(duration.Nanoseconds()) / 1e6, // Convert to milliseconds
			UserID:        getStringFromContext(c.Request.Context(), "user_id"),
			RequestID:     getStringFromContext(c.Request.Context(), "request_id"),
			TraceID:       getStringFromContext(c.Request.Context(), "trace_id"),
			CorrelationID: getStringFromContext(c.Request.Context(), "correlation_id"),
			ClientIP:      c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			StatusCode:    c.Writer.Status(),
			Fields: map[string]interface{}{
				"method":        c.Request.Method,
				"path":          c.Request.URL.Path,
				"status_code":   c.Writer.Status(),
				"duration_ms":   duration.Milliseconds(),
				"request_size":  c.Request.ContentLength,
				"response_size": c.Writer.Size(),
			},
		}

		// Add error information if present
		if len(c.Errors) > 0 {
			entry.Error = c.Errors.String()
		}

		s.aggregator.AddLogEntry(entry)
	}
}

// // generateID generates a random ID (helper function)
// func generateID() string {
// 	return strconv.FormatInt(time.Now().UnixNano(), 36)
// }
