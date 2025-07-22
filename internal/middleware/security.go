package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// SecurityConfig holds configuration for security middleware
type SecurityConfig struct {
	// Suspicious activity detection
	MaxLoginAttemptsPerIP   int           `yaml:"max_login_attempts_per_ip"`
	MaxLoginAttemptsWindow  time.Duration `yaml:"max_login_attempts_window"`
	MaxDifferentUsersPerIP  int           `yaml:"max_different_users_per_ip"`
	MaxDifferentUsersWindow time.Duration `yaml:"max_different_users_window"`

	// Geolocation anomaly detection
	EnableGeoAnomalyDetection bool    `yaml:"enable_geo_anomaly_detection"`
	MaxDistanceKm             float64 `yaml:"max_distance_km"`

	// Device fingerprinting
	EnableDeviceFingerprinting bool `yaml:"enable_device_fingerprinting"`
	MaxDevicesPerUser          int  `yaml:"max_devices_per_user"`

	// Time-based anomalies
	EnableTimeAnomalyDetection bool `yaml:"enable_time_anomaly_detection"`
	UnusualHourThreshold       int  `yaml:"unusual_hour_threshold"` // Hour of day (0-23)

	// Blocked IPs and user agents
	BlockedIPs        []string `yaml:"blocked_ips"`
	BlockedUserAgents []string `yaml:"blocked_user_agents"`

	// Response configuration
	BlockSuspiciousRequests bool `yaml:"block_suspicious_requests"`
	LogSuspiciousActivity   bool `yaml:"log_suspicious_activity"`
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxLoginAttemptsPerIP:      20,
		MaxLoginAttemptsWindow:     time.Hour,
		MaxDifferentUsersPerIP:     10,
		MaxDifferentUsersWindow:    time.Hour,
		EnableGeoAnomalyDetection:  false, // Requires external geo service
		MaxDistanceKm:              1000,
		EnableDeviceFingerprinting: true,
		MaxDevicesPerUser:          5,
		EnableTimeAnomalyDetection: false,
		UnusualHourThreshold:       2, // 2 AM
		BlockedIPs:                 []string{},
		BlockedUserAgents:          []string{"bot", "crawler", "spider"},
		BlockSuspiciousRequests:    true,
		LogSuspiciousActivity:      true,
	}
}

// SuspiciousActivity represents detected suspicious activity
type SuspiciousActivity struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"` // low, medium, high, critical
	Description string                 `json:"description"`
	IP          string                 `json:"ip"`
	UserAgent   string                 `json:"user_agent"`
	UserID      string                 `json:"user_id,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityMiddleware provides security monitoring and threat detection
type SecurityMiddleware struct {
	config      *SecurityConfig
	redisClient *redis.Client
	rateLimiter *redis.RateLimiter
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(config *SecurityConfig, redisClient *redis.Client) *SecurityMiddleware {
	return &SecurityMiddleware{
		config:      config,
		redisClient: redisClient,
		rateLimiter: redis.NewRateLimiter(redisClient, time.Hour),
	}
}

// Handler returns the Gin middleware handler
func (sm *SecurityMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Check for blocked IPs and user agents
		if sm.isBlocked(c) {
			sm.logSuspiciousActivity(ctx, &SuspiciousActivity{
				Type:        "blocked_request",
				Severity:    "high",
				Description: "Request from blocked IP or user agent",
				IP:          sm.getClientIP(c),
				UserAgent:   c.GetHeader("User-Agent"),
				Timestamp:   time.Now(),
			})

			if sm.config.BlockSuspiciousRequests {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "access denied",
				})
				c.Abort()
				return
			}
		}

		// Detect suspicious patterns
		activities := sm.detectSuspiciousActivity(ctx, c)
		for _, activity := range activities {
			sm.logSuspiciousActivity(ctx, activity)

			// Block critical threats
			if activity.Severity == "critical" && sm.config.BlockSuspiciousRequests {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "suspicious activity detected",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// isBlocked checks if the request should be blocked
func (sm *SecurityMiddleware) isBlocked(c *gin.Context) bool {
	clientIP := sm.getClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	// Check blocked IPs
	for _, blockedIP := range sm.config.BlockedIPs {
		if clientIP == blockedIP || sm.isIPInCIDR(clientIP, blockedIP) {
			return true
		}
	}

	// Check blocked user agents
	for _, blockedUA := range sm.config.BlockedUserAgents {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(blockedUA)) {
			return true
		}
	}

	return false
}

// isIPInCIDR checks if an IP is in a CIDR range
func (sm *SecurityMiddleware) isIPInCIDR(ip, cidr string) bool {
	if !strings.Contains(cidr, "/") {
		return false
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return network.Contains(parsedIP)
}

// detectSuspiciousActivity detects various suspicious patterns
func (sm *SecurityMiddleware) detectSuspiciousActivity(ctx context.Context, c *gin.Context) []*SuspiciousActivity {
	var activities []*SuspiciousActivity

	clientIP := sm.getClientIP(c)
	userAgent := c.GetHeader("User-Agent")
	path := c.Request.URL.Path
	method := c.Request.Method

	// Detect rapid login attempts from same IP
	if sm.isLoginEndpoint(path, method) {
		if activity := sm.detectRapidLoginAttempts(ctx, clientIP); activity != nil {
			activities = append(activities, activity)
		}
	}

	// Detect multiple user attempts from same IP
	if sm.isLoginEndpoint(path, method) {
		if activity := sm.detectMultipleUserAttempts(ctx, clientIP, c); activity != nil {
			activities = append(activities, activity)
		}
	}

	// Detect unusual user agent patterns
	if activity := sm.detectUnusualUserAgent(userAgent, clientIP); activity != nil {
		activities = append(activities, activity)
	}

	// Detect time-based anomalies
	if sm.config.EnableTimeAnomalyDetection {
		if activity := sm.detectTimeAnomaly(clientIP); activity != nil {
			activities = append(activities, activity)
		}
	}

	// Detect device fingerprint anomalies
	if sm.config.EnableDeviceFingerprinting {
		if activity := sm.detectDeviceAnomaly(ctx, c); activity != nil {
			activities = append(activities, activity)
		}
	}

	return activities
}

// detectRapidLoginAttempts detects rapid login attempts from the same IP
func (sm *SecurityMiddleware) detectRapidLoginAttempts(ctx context.Context, clientIP string) *SuspiciousActivity {
	key := fmt.Sprintf("login_attempts:ip:%s", clientIP)

	result, err := sm.rateLimiter.Allow(ctx, key, int64(sm.config.MaxLoginAttemptsPerIP))
	if err != nil {
		return nil
	}

	if !result.Allowed {
		return &SuspiciousActivity{
			Type:        "rapid_login_attempts",
			Severity:    "high",
			Description: fmt.Sprintf("Too many login attempts from IP %s", clientIP),
			IP:          clientIP,
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"attempts": result.Count,
				"limit":    result.Limit,
			},
		}
	}

	// Warn at 80% of limit
	if result.Count > int64(float64(sm.config.MaxLoginAttemptsPerIP)*0.8) {
		return &SuspiciousActivity{
			Type:        "elevated_login_attempts",
			Severity:    "medium",
			Description: fmt.Sprintf("Elevated login attempts from IP %s", clientIP),
			IP:          clientIP,
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"attempts": result.Count,
				"limit":    result.Limit,
			},
		}
	}

	return nil
}

// detectMultipleUserAttempts detects attempts to login as multiple different users from same IP
func (sm *SecurityMiddleware) detectMultipleUserAttempts(ctx context.Context, clientIP string, c *gin.Context) *SuspiciousActivity {
	// Extract username/email from request body (this is a simplified approach)
	username := sm.extractUsernameFromRequest(c)
	if username == "" {
		return nil
	}

	key := fmt.Sprintf("user_attempts:ip:%s", clientIP)
	userKey := fmt.Sprintf("%s:user:%s", key, username)

	// Track unique users attempted from this IP
	err := sm.redisClient.SAdd(ctx, key, username).Err()
	if err != nil {
		return nil
	}

	// Set expiration
	sm.redisClient.Expire(ctx, key, sm.config.MaxDifferentUsersWindow)
	sm.redisClient.Expire(ctx, userKey, sm.config.MaxDifferentUsersWindow)

	// Count unique users
	count, err := sm.redisClient.SCard(ctx, key).Result()
	if err != nil {
		return nil
	}

	if int(count) > sm.config.MaxDifferentUsersPerIP {
		return &SuspiciousActivity{
			Type:        "multiple_user_attempts",
			Severity:    "high",
			Description: fmt.Sprintf("Multiple user login attempts from IP %s", clientIP),
			IP:          clientIP,
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"unique_users": count,
				"limit":        sm.config.MaxDifferentUsersPerIP,
				"current_user": username,
			},
		}
	}

	return nil
}

// detectUnusualUserAgent detects suspicious user agent patterns
func (sm *SecurityMiddleware) detectUnusualUserAgent(userAgent, clientIP string) *SuspiciousActivity {
	if userAgent == "" {
		return &SuspiciousActivity{
			Type:        "missing_user_agent",
			Severity:    "medium",
			Description: "Request without User-Agent header",
			IP:          clientIP,
			UserAgent:   userAgent,
			Timestamp:   time.Now(),
		}
	}

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"curl", "wget", "python", "go-http-client", "java",
		"scanner", "exploit", "attack", "hack",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return &SuspiciousActivity{
				Type:        "suspicious_user_agent",
				Severity:    "medium",
				Description: fmt.Sprintf("Suspicious user agent pattern: %s", pattern),
				IP:          clientIP,
				UserAgent:   userAgent,
				Timestamp:   time.Now(),
				Metadata: map[string]interface{}{
					"pattern": pattern,
				},
			}
		}
	}

	return nil
}

// detectTimeAnomaly detects unusual login times
func (sm *SecurityMiddleware) detectTimeAnomaly(clientIP string) *SuspiciousActivity {
	now := time.Now()
	hour := now.Hour()

	// Check if login is during unusual hours (e.g., 2-6 AM)
	if hour >= sm.config.UnusualHourThreshold && hour < sm.config.UnusualHourThreshold+4 {
		return &SuspiciousActivity{
			Type:        "unusual_time_access",
			Severity:    "low",
			Description: fmt.Sprintf("Login attempt during unusual hours (%d:00)", hour),
			IP:          clientIP,
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"hour": hour,
			},
		}
	}

	return nil
}

// detectDeviceAnomaly detects device fingerprint anomalies
func (sm *SecurityMiddleware) detectDeviceAnomaly(ctx context.Context, c *gin.Context) *SuspiciousActivity {
	userID := sm.getUserID(c)
	if userID == "" {
		return nil
	}

	deviceFingerprint := sm.generateDeviceFingerprint(c)
	key := fmt.Sprintf("devices:user:%s", userID)

	// Add device fingerprint to user's device set
	err := sm.redisClient.SAdd(ctx, key, deviceFingerprint).Err()
	if err != nil {
		return nil
	}

	// Set expiration (30 days)
	sm.redisClient.Expire(ctx, key, 30*24*time.Hour)

	// Count devices
	count, err := sm.redisClient.SCard(ctx, key).Result()
	if err != nil {
		return nil
	}

	if int(count) > sm.config.MaxDevicesPerUser {
		return &SuspiciousActivity{
			Type:        "too_many_devices",
			Severity:    "medium",
			Description: fmt.Sprintf("User %s has too many devices", userID),
			IP:          sm.getClientIP(c),
			UserID:      userID,
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"device_count":       count,
				"limit":              sm.config.MaxDevicesPerUser,
				"device_fingerprint": deviceFingerprint,
			},
		}
	}

	return nil
}

// generateDeviceFingerprint creates a device fingerprint based on headers
func (sm *SecurityMiddleware) generateDeviceFingerprint(c *gin.Context) string {
	components := []string{
		c.GetHeader("User-Agent"),
		c.GetHeader("Accept"),
		c.GetHeader("Accept-Language"),
		c.GetHeader("Accept-Encoding"),
	}

	fingerprint := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// isLoginEndpoint checks if the current request is to a login endpoint
func (sm *SecurityMiddleware) isLoginEndpoint(path, method string) bool {
	loginPaths := []string{
		"/api/v1/auth/login",
		"/auth/login",
		"/login",
	}

	if method != "POST" {
		return false
	}

	for _, loginPath := range loginPaths {
		if strings.HasSuffix(path, loginPath) {
			return true
		}
	}

	return false
}

// extractUsernameFromRequest extracts username/email from request (simplified)
func (sm *SecurityMiddleware) extractUsernameFromRequest(c *gin.Context) string {
	// This is a simplified approach - in practice, you'd parse the JSON body
	// For now, we'll try to get it from form data or query params
	if username := c.PostForm("username"); username != "" {
		return username
	}
	if email := c.PostForm("email"); email != "" {
		return email
	}
	if username := c.Query("username"); username != "" {
		return username
	}
	if email := c.Query("email"); email != "" {
		return email
	}
	return ""
}

// getClientIP extracts the client IP address from the request
func (sm *SecurityMiddleware) getClientIP(c *gin.Context) string {
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
func (sm *SecurityMiddleware) getUserID(c *gin.Context) string {
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

// logSuspiciousActivity logs suspicious activity
func (sm *SecurityMiddleware) logSuspiciousActivity(ctx context.Context, activity *SuspiciousActivity) {
	if !sm.config.LogSuspiciousActivity {
		return
	}

	// Store in Redis for analysis
	key := fmt.Sprintf("suspicious_activity:%s:%d", activity.Type, activity.Timestamp.Unix())

	// Store activity data (in practice, you might want to use a proper logging system)
	sm.redisClient.HSet(ctx, key,
		"type", activity.Type,
		"severity", activity.Severity,
		"description", activity.Description,
		"ip", activity.IP,
		"user_agent", activity.UserAgent,
		"user_id", activity.UserID,
		"timestamp", activity.Timestamp.Unix(),
	)

	// Set expiration (7 days)
	sm.redisClient.Expire(ctx, key, 7*24*time.Hour)

	// Also add to a sorted set for easy querying
	sm.redisClient.ZAdd(ctx, "suspicious_activities", &redis.Z{
		Score:  float64(activity.Timestamp.Unix()),
		Member: key,
	})
	sm.redisClient.Expire(ctx, "suspicious_activities", 7*24*time.Hour)
}

// GetSuspiciousActivities retrieves recent suspicious activities
func (sm *SecurityMiddleware) GetSuspiciousActivities(ctx context.Context, limit int64) ([]*SuspiciousActivity, error) {
	// Get recent activities from sorted set
	keys, err := sm.redisClient.ZRevRange(ctx, "suspicious_activities", 0, limit-1).Result()
	if err != nil {
		return nil, err
	}

	var activities []*SuspiciousActivity
	for _, key := range keys {
		data, err := sm.redisClient.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}

		activity := &SuspiciousActivity{
			Type:        data["type"],
			Severity:    data["severity"],
			Description: data["description"],
			IP:          data["ip"],
			UserAgent:   data["user_agent"],
			UserID:      data["user_id"],
		}

		if timestamp := data["timestamp"]; timestamp != "" {
			if ts, err := time.Parse("1136239445", timestamp); err == nil {
				activity.Timestamp = ts
			}
		}

		activities = append(activities, activity)
	}

	return activities, nil
}
