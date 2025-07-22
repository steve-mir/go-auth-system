package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// Config holds configuration for all middleware components
type Config struct {
	RateLimit *RateLimitConfig `yaml:"rate_limit"`
	Security  *SecurityConfig  `yaml:"security"`
}

// DefaultConfig returns default middleware configuration
func DefaultConfig() *Config {
	return &Config{
		RateLimit: DefaultRateLimitConfig(),
		Security:  DefaultSecurityConfig(),
	}
}

// MiddlewareManager manages all security and rate limiting middleware
type MiddlewareManager struct {
	rateLimitMiddleware *RateLimitMiddleware
	securityMiddleware  *SecurityMiddleware
	config              *Config
}

// NewMiddlewareManager creates a new middleware manager
func NewMiddlewareManager(config *Config, redisClient *redis.Client) *MiddlewareManager {
	return &MiddlewareManager{
		rateLimitMiddleware: NewRateLimitMiddleware(config.RateLimit, redisClient),
		securityMiddleware:  NewSecurityMiddleware(config.Security, redisClient),
		config:              config,
	}
}

// RateLimitHandler returns the rate limiting middleware handler
func (mm *MiddlewareManager) RateLimitHandler() gin.HandlerFunc {
	return mm.rateLimitMiddleware.Handler()
}

// SecurityHandler returns the security middleware handler
func (mm *MiddlewareManager) SecurityHandler() gin.HandlerFunc {
	return mm.securityMiddleware.Handler()
}

// CombinedSecurityHandler returns a combined security and rate limiting handler
func (mm *MiddlewareManager) CombinedSecurityHandler() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Apply security middleware first
		mm.securityMiddleware.Handler()(c)
		if c.IsAborted() {
			return
		}

		// Then apply rate limiting
		mm.rateLimitMiddleware.Handler()(c)
		if c.IsAborted() {
			return
		}

		c.Next()
	})
}

// GetRateLimitMiddleware returns the rate limit middleware instance
func (mm *MiddlewareManager) GetRateLimitMiddleware() *RateLimitMiddleware {
	return mm.rateLimitMiddleware
}

// GetSecurityMiddleware returns the security middleware instance
func (mm *MiddlewareManager) GetSecurityMiddleware() *SecurityMiddleware {
	return mm.securityMiddleware
}

// AuthenticationMiddleware provides authentication validation
type AuthenticationMiddleware struct {
	// This would typically integrate with your token service
	// For now, we'll provide a basic structure
}

// NewAuthenticationMiddleware creates a new authentication middleware
func NewAuthenticationMiddleware() *AuthenticationMiddleware {
	return &AuthenticationMiddleware{}
}

// Handler returns the authentication middleware handler
func (am *AuthenticationMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// Validate token (this would integrate with your token service)
		// For now, we'll just check if it starts with "Bearer "
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(401, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		token := authHeader[7:]
		if token == "" {
			c.JSON(401, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		// TODO: Validate token with token service
		// For now, we'll set a dummy user ID
		c.Set("user_id", "dummy-user-id")
		c.Set("token", token)

		c.Next()
	}
}

// CORSMiddleware provides CORS support
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID (in production, use a proper UUID library)
			requestID = generateRequestID()
		}

		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	})
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	// This is a simplified implementation
	// In production, use a proper UUID library like github.com/google/uuid
	return time.Now().Format("20060102150405") + "-" + "req"
}

// LoggingMiddleware provides request logging
func LoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// RecoveryMiddleware provides panic recovery
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.JSON(500, gin.H{
				"error":      "internal server error",
				"request_id": c.GetString("request_id"),
			})
			// Log the error (in production, use proper logging)
			println("Panic recovered:", err)
		}
		c.AbortWithStatus(500)
	})
}

// HealthCheckMiddleware provides health check endpoints
func HealthCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/healthz" {
			c.JSON(200, gin.H{
				"status":    "healthy",
				"timestamp": time.Now().Unix(),
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// MetricsMiddleware provides basic metrics collection
type MetricsMiddleware struct {
	requestCount map[string]int64
	// In production, use proper metrics library like Prometheus
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware() *MetricsMiddleware {
	return &MetricsMiddleware{
		requestCount: make(map[string]int64),
	}
}

// Handler returns the metrics middleware handler
func (mm *MetricsMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Record metrics
		duration := time.Since(start)
		path := c.Request.URL.Path
		method := c.Request.Method
		status := c.Writer.Status()

		// In production, send these to a proper metrics system
		key := method + " " + path
		mm.requestCount[key]++

		// Log metrics (in production, use proper metrics collection)
		if duration > 1*time.Second {
			println("Slow request:", key, "took", duration.String(), "status", status)
		}
	}
}

// GetMetrics returns current metrics
func (mm *MetricsMiddleware) GetMetrics() map[string]int64 {
	return mm.requestCount
}
