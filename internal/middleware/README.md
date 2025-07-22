# Middleware Package

This package provides comprehensive security and rate limiting middleware for the Go authentication system. It implements sliding window rate limiting, suspicious activity detection, account lockout policies, and various security measures.

## Features

### Rate Limiting
- **Sliding Window Algorithm**: Implements precise sliding window rate limiting using Redis
- **Multi-Level Limits**: Global, per-IP, and per-user rate limiting
- **Configurable Windows**: Customizable time windows for different rate limits
- **Rate Limit Headers**: Includes standard rate limit headers in responses

### Security Middleware
- **Suspicious Activity Detection**: Detects various suspicious patterns
- **Account Lockout**: Progressive account lockout with configurable policies
- **Device Fingerprinting**: Tracks and limits devices per user
- **IP and User Agent Blocking**: Configurable IP and user agent blacklists
- **Time-based Anomaly Detection**: Detects unusual access times
- **Multiple User Attempts**: Detects attempts to access multiple accounts from same IP

### Additional Middleware
- **CORS Support**: Configurable Cross-Origin Resource Sharing
- **Request ID**: Unique request ID generation and tracking
- **Authentication**: Token-based authentication validation
- **Health Checks**: Built-in health check endpoints
- **Metrics Collection**: Basic request metrics and performance monitoring
- **Panic Recovery**: Graceful panic recovery with proper error responses
- **Logging**: Structured request logging

## Usage

### Basic Setup

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/steve-mir/go-auth-system/internal/middleware"
    "github.com/steve-mir/go-auth-system/internal/repository/redis"
)

func main() {
    // Initialize Redis client
    redisClient, err := redis.NewClient(&redis.Config{
        Host: "localhost",
        Port: 6379,
        DB:   0,
    })
    if err != nil {
        panic(err)
    }
    defer redisClient.Close()

    // Create middleware configuration
    config := middleware.DefaultConfig()
    
    // Customize configuration as needed
    config.RateLimit.GlobalLimit = 1000
    config.RateLimit.IPLimit = 100
    config.Security.BlockedIPs = []string{"192.168.1.100"}

    // Create middleware manager
    manager := middleware.NewMiddlewareManager(config, redisClient)

    // Set up Gin router
    router := gin.New()
    
    // Add middleware stack
    router.Use(middleware.RequestIDMiddleware())
    router.Use(middleware.CORSMiddleware())
    router.Use(middleware.HealthCheckMiddleware())
    router.Use(middleware.RecoveryMiddleware())
    router.Use(manager.CombinedSecurityHandler())

    // Add routes
    router.POST("/api/v1/auth/login", loginHandler)
    
    // Protected routes
    protected := router.Group("/api/v1")
    protected.Use(middleware.NewAuthenticationMiddleware().Handler())
    protected.GET("/profile", profileHandler)

    router.Run(":8080")
}
```

### Individual Middleware Usage

```go
// Use only rate limiting
router.Use(manager.RateLimitHandler())

// Use only security middleware
router.Use(manager.SecurityHandler())

// Use combined security and rate limiting
router.Use(manager.CombinedSecurityHandler())
```

### Configuration

#### Rate Limiting Configuration

```go
rateLimitConfig := &middleware.RateLimitConfig{
    GlobalLimit:       1000,              // Global requests per window
    GlobalWindow:      time.Hour,         // Global window duration
    IPLimit:           100,               // Per-IP requests per window
    IPWindow:          time.Hour,         // Per-IP window duration
    UserLimit:         200,               // Per-user requests per window
    UserWindow:        time.Hour,         // Per-user window duration
    MaxFailedAttempts: 5,                 // Max failed attempts before lockout
    LockoutDuration:   time.Hour,         // Account lockout duration
    SkipPaths:         []string{"/health"}, // Paths to skip rate limiting
    IncludeHeaders:    true,              // Include rate limit headers
}
```

#### Security Configuration

```go
securityConfig := &middleware.SecurityConfig{
    MaxLoginAttemptsPerIP:      20,                    // Max login attempts per IP
    MaxLoginAttemptsWindow:     time.Hour,             // Login attempts window
    MaxDifferentUsersPerIP:     10,                    // Max different users per IP
    MaxDifferentUsersWindow:    time.Hour,             // Different users window
    EnableGeoAnomalyDetection:  false,                 // Enable geo-based detection
    MaxDistanceKm:              1000,                  // Max distance for geo anomaly
    EnableDeviceFingerprinting: true,                  // Enable device fingerprinting
    MaxDevicesPerUser:          5,                     // Max devices per user
    EnableTimeAnomalyDetection: false,                 // Enable time-based detection
    UnusualHourThreshold:       2,                     // Unusual hour threshold (2 AM)
    BlockedIPs:                 []string{"10.0.0.1"}, // Blocked IP addresses
    BlockedUserAgents:          []string{"bot"},       // Blocked user agents
    BlockSuspiciousRequests:    true,                  // Block suspicious requests
    LogSuspiciousActivity:      true,                  // Log suspicious activity
}
```

## Account Lockout Management

The middleware provides methods to manage account lockouts:

```go
rateLimitMW := manager.GetRateLimitMiddleware()

// Record a failed login attempt
result, err := rateLimitMW.RecordFailedLogin(ctx, "user@example.com")
if err != nil {
    // Handle error
}
if result.Blocked {
    // Account is now locked
    fmt.Printf("Account locked until: %v\n", result.Until)
}

// Check if account is locked
lockStatus, err := rateLimitMW.IsAccountLocked(ctx, "user@example.com")
if err != nil {
    // Handle error
}
if lockStatus.Blocked {
    // Account is locked
}

// Clear failed attempts (after successful login)
err = rateLimitMW.ClearFailedAttempts(ctx, "user@example.com")

// Manually unlock account (admin action)
err = rateLimitMW.UnlockAccount(ctx, "user@example.com")
```

## Suspicious Activity Monitoring

Monitor and retrieve suspicious activities:

```go
securityMW := manager.GetSecurityMiddleware()

// Get recent suspicious activities
activities, err := securityMW.GetSuspiciousActivities(ctx, 50)
if err != nil {
    // Handle error
}

for _, activity := range activities {
    fmt.Printf("Suspicious activity: %s from %s at %v\n", 
        activity.Type, activity.IP, activity.Timestamp)
}
```

## Rate Limit Headers

When `IncludeHeaders` is enabled, the following headers are included in responses:

- `X-RateLimit-Global-Limit`: Global rate limit
- `X-RateLimit-Global-Remaining`: Remaining global requests
- `X-RateLimit-Global-Reset`: Global rate limit reset time
- `X-RateLimit-IP-Limit`: IP rate limit
- `X-RateLimit-IP-Remaining`: Remaining IP requests
- `X-RateLimit-IP-Reset`: IP rate limit reset time
- `X-RateLimit-User-Limit`: User rate limit
- `X-RateLimit-User-Remaining`: Remaining user requests
- `X-RateLimit-User-Reset`: User rate limit reset time
- `Retry-After`: Seconds to wait before retrying (when rate limited)

## Suspicious Activity Types

The security middleware detects the following types of suspicious activities:

- `blocked_request`: Request from blocked IP or user agent
- `rapid_login_attempts`: Too many login attempts from same IP
- `elevated_login_attempts`: High number of login attempts (warning level)
- `multiple_user_attempts`: Attempts to login as multiple users from same IP
- `missing_user_agent`: Request without User-Agent header
- `suspicious_user_agent`: User agent matching suspicious patterns
- `unusual_time_access`: Access during unusual hours
- `too_many_devices`: User has too many registered devices

## Error Responses

### Rate Limit Exceeded

```json
{
  "error": "rate limit exceeded",
  "retry_after": 3600
}
```

### Suspicious Activity Detected

```json
{
  "error": "suspicious activity detected"
}
```

### Access Denied

```json
{
  "error": "access denied"
}
```

## Testing

The package includes comprehensive tests:

```bash
# Run all middleware tests
go test ./internal/middleware/...

# Run with verbose output
go test -v ./internal/middleware/...

# Run integration tests
go test -v ./internal/middleware/ -run TestMiddlewareIntegration
```

## Dependencies

- **Gin**: Web framework for HTTP handling
- **Redis**: For rate limiting and suspicious activity storage
- **Testify**: For testing utilities

## Performance Considerations

- **Redis Operations**: All rate limiting operations use atomic Redis operations
- **Lua Scripts**: Complex Redis operations use Lua scripts for atomicity
- **Memory Usage**: Device fingerprints and suspicious activities have TTL for cleanup
- **Header Overhead**: Rate limit headers add minimal response overhead
- **Logging**: Suspicious activity logging is asynchronous where possible

## Security Best Practices

1. **Configure Appropriate Limits**: Set rate limits based on your application's needs
2. **Monitor Suspicious Activities**: Regularly review suspicious activity logs
3. **Update Blocked Lists**: Keep IP and user agent blacklists updated
4. **Use HTTPS**: Always use HTTPS in production
5. **Secure Redis**: Ensure Redis instance is properly secured
6. **Log Analysis**: Implement proper log analysis and alerting
7. **Regular Updates**: Keep dependencies updated for security patches

## Production Deployment

For production deployment:

1. **Redis Clustering**: Use Redis cluster for high availability
2. **Monitoring**: Implement proper monitoring and alerting
3. **Log Aggregation**: Use centralized logging systems
4. **Rate Limit Tuning**: Monitor and adjust rate limits based on traffic patterns
5. **Security Updates**: Regularly update security configurations
6. **Performance Testing**: Load test rate limiting under expected traffic