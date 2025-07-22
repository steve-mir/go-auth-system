package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// RateLimitConfig holds configuration for rate limiting middleware
type RateLimitConfig struct {
	// Global rate limits
	GlobalLimit  int64         `yaml:"global_limit"`
	GlobalWindow time.Duration `yaml:"global_window"`

	// Per-IP rate limits
	IPLimit  int64         `yaml:"ip_limit"`
	IPWindow time.Duration `yaml:"ip_window"`

	// Per-user rate limits
	UserLimit  int64         `yaml:"user_limit"`
	UserWindow time.Duration `yaml:"user_window"`

	// Account lockout settings
	MaxFailedAttempts int           `yaml:"max_failed_attempts"`
	LockoutDuration   time.Duration `yaml:"lockout_duration"`

	// Skip rate limiting for certain paths
	SkipPaths []string `yaml:"skip_paths"`

	// Headers to include in response
	IncludeHeaders bool `yaml:"include_headers"`
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		GlobalLimit:       1000,
		GlobalWindow:      time.Hour,
		IPLimit:           100,
		IPWindow:          time.Hour,
		UserLimit:         200,
		UserWindow:        time.Hour,
		MaxFailedAttempts: 5,
		LockoutDuration:   time.Hour,
		SkipPaths:         []string{"/health", "/metrics"},
		IncludeHeaders:    true,
	}
}

// RateLimitMiddleware provides rate limiting functionality
type RateLimitMiddleware struct {
	config         *RateLimitConfig
	globalLimiter  *redis.RateLimiter
	ipLimiter      *redis.RateLimiter
	userLimiter    *redis.RateLimiter
	accountLockout *redis.AccountLockout
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(config *RateLimitConfig, redisClient *redis.Client) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		config:         config,
		globalLimiter:  redis.NewRateLimiter(redisClient, config.GlobalWindow),
		ipLimiter:      redis.NewRateLimiter(redisClient, config.IPWindow),
		userLimiter:    redis.NewRateLimiter(redisClient, config.UserWindow),
		accountLockout: redis.NewAccountLockout(redisClient),
	}
}

// Handler returns the Gin middleware handler
func (rlm *RateLimitMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting for certain paths
		if rlm.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		ctx := c.Request.Context()

		// Check global rate limit
		if err := rlm.checkGlobalLimit(ctx, c); err != nil {
			return
		}

		// Check IP-based rate limit
		if err := rlm.checkIPLimit(ctx, c); err != nil {
			return
		}

		// Check user-based rate limit (if authenticated)
		if err := rlm.checkUserLimit(ctx, c); err != nil {
			return
		}

		c.Next()
	}
}

// shouldSkipPath checks if the path should skip rate limiting
func (rlm *RateLimitMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range rlm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// checkGlobalLimit checks the global rate limit
func (rlm *RateLimitMiddleware) checkGlobalLimit(ctx context.Context, c *gin.Context) error {
	result, err := rlm.globalLimiter.Allow(ctx, "global", rlm.config.GlobalLimit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "rate limit check failed",
		})
		c.Abort()
		return err
	}

	if rlm.config.IncludeHeaders {
		rlm.setRateLimitHeaders(c, result, "Global")
	}

	if !result.Allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "global rate limit exceeded",
			"retry_after": int(result.RetryAfter.Seconds()),
		})
		c.Abort()
		return fmt.Errorf("global rate limit exceeded")
	}

	return nil
}

// checkIPLimit checks the IP-based rate limit
func (rlm *RateLimitMiddleware) checkIPLimit(ctx context.Context, c *gin.Context) error {
	clientIP := rlm.getClientIP(c)
	if clientIP == "" {
		return nil // Skip if we can't determine IP
	}

	result, err := rlm.ipLimiter.Allow(ctx, "ip:"+clientIP, rlm.config.IPLimit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "rate limit check failed",
		})
		c.Abort()
		return err
	}

	if rlm.config.IncludeHeaders {
		rlm.setRateLimitHeaders(c, result, "IP")
	}

	if !result.Allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "IP rate limit exceeded",
			"retry_after": int(result.RetryAfter.Seconds()),
		})
		c.Abort()
		return fmt.Errorf("IP rate limit exceeded")
	}

	return nil
}

// checkUserLimit checks the user-based rate limit
func (rlm *RateLimitMiddleware) checkUserLimit(ctx context.Context, c *gin.Context) error {
	userID := rlm.getUserID(c)
	if userID == "" {
		return nil // Skip if user is not authenticated
	}

	result, err := rlm.userLimiter.Allow(ctx, "user:"+userID, rlm.config.UserLimit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "rate limit check failed",
		})
		c.Abort()
		return err
	}

	if rlm.config.IncludeHeaders {
		rlm.setRateLimitHeaders(c, result, "User")
	}

	if !result.Allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "user rate limit exceeded",
			"retry_after": int(result.RetryAfter.Seconds()),
		})
		c.Abort()
		return fmt.Errorf("user rate limit exceeded")
	}

	return nil
}

// setRateLimitHeaders sets rate limit headers in the response
func (rlm *RateLimitMiddleware) setRateLimitHeaders(c *gin.Context, result *redis.RateLimitResult, prefix string) {
	c.Header(fmt.Sprintf("X-RateLimit-%s-Limit", prefix), strconv.FormatInt(result.Limit, 10))
	c.Header(fmt.Sprintf("X-RateLimit-%s-Remaining", prefix), strconv.FormatInt(result.Remaining, 10))
	c.Header(fmt.Sprintf("X-RateLimit-%s-Reset", prefix), strconv.FormatInt(result.ResetTime.Unix(), 10))

	if !result.Allowed {
		c.Header("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
	}
}

// getClientIP extracts the client IP address from the request
func (rlm *RateLimitMiddleware) getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}

	if net.ParseIP(ip) != nil {
		return ip
	}

	return ""
}

// getUserID extracts the user ID from the request context
func (rlm *RateLimitMiddleware) getUserID(c *gin.Context) string {
	// Try to get user ID from context (set by auth middleware)
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			return uid
		}
	}

	// Try to get from claims
	if claims, exists := c.Get("claims"); exists {
		if claimsMap, ok := claims.(map[string]interface{}); ok {
			if userID, exists := claimsMap["user_id"]; exists {
				if uid, ok := userID.(string); ok {
					return uid
				}
			}
		}
	}

	return ""
}

// RecordFailedLogin records a failed login attempt for account lockout
func (rlm *RateLimitMiddleware) RecordFailedLogin(ctx context.Context, identifier string) (*redis.BlockedUntil, error) {
	return rlm.accountLockout.RecordFailedAttempt(ctx, identifier, rlm.config.MaxFailedAttempts, rlm.config.LockoutDuration)
}

// IsAccountLocked checks if an account is currently locked
func (rlm *RateLimitMiddleware) IsAccountLocked(ctx context.Context, identifier string) (*redis.BlockedUntil, error) {
	return rlm.accountLockout.IsBlocked(ctx, identifier)
}

// ClearFailedAttempts clears failed login attempts (after successful login)
func (rlm *RateLimitMiddleware) ClearFailedAttempts(ctx context.Context, identifier string) error {
	return rlm.accountLockout.ClearFailedAttempts(ctx, identifier)
}

// UnlockAccount manually unlocks an account
func (rlm *RateLimitMiddleware) UnlockAccount(ctx context.Context, identifier string) error {
	return rlm.accountLockout.UnlockAccount(ctx, identifier)
}
